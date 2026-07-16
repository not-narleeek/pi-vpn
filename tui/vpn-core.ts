/**
 * Framework-agnostic OpenVPN management core for the pi-vpn standalone TUI.
 *
 * This is deliberately free of any pi / TUI / rendering concerns: it owns the
 * VPN lifecycle (connect / disconnect / monitor / status / reattach), the
 * privilege model, credential handling, .ovpn discovery, and persistence.
 * The TUI (vpn-tui.ts) imports only from here.
 *
 * Philosophy: stdlib only, no npm runtime deps. Mirrors the behaviour of the
 * pi extension (extensions/vpn.ts) so both stay in sync conceptually.
 */

import { spawnSync } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	readFileSync,
	readdirSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, extname, join, resolve } from "node:path";

// ---------------------------------------------------------------------------
// Constants & paths
// ---------------------------------------------------------------------------

export const DATA_DIR = join(homedir(), ".pi", "vpn");
export const LOG_DIR = join(DATA_DIR, "logs");
export const PID_DIR = join(DATA_DIR, "pid");
export const STATE_FILE = join(DATA_DIR, "state.json");

const MONITOR_TIMEOUT_MS = 60_000;
const MONITOR_INTERVAL_MS = 500;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Status = "disconnected" | "connecting" | "connected" | "error";

export interface VpnInfo {
	name: string;
	configPath: string;
	status: Status;
	ip: string | null;
	dev: string | null;
	pid: number | null;
	startTime: number | null; // epoch ms when CONNECTED (for elapsed)
	connectTime: number | null; // epoch ms when connect attempt began
	error: string | null;
}

export interface ConnectOptions {
	configPath: string;
	name?: string;
	username?: string;
	password?: string;
	authFile?: string;
}

interface PersistedState {
	name: string;
	configPath: string;
	pid: number | null;
	startTime: number | null;
	dev: string | null;
}

/**
 * Minimal UI surface the manager needs for interactive prompts.
 * The TUI implements this with masked raw-mode input; a CLI can implement it
 * with readline. `prompt` resolves to the string, or `undefined` if cancelled.
 */
export interface UiAdapter {
	prompt(label: string, opts?: { secret?: boolean }): Promise<string | undefined>;
	log?(msg: string): void;
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

export function ensureDirs(): void {
	mkdirSync(LOG_DIR, { recursive: true });
	mkdirSync(PID_DIR, { recursive: true });
}

export function isRoot(): boolean {
	return typeof process.getuid === "function" && process.getuid() === 0;
}

export function nameFromPath(configPath: string): string {
	const base = basename(configPath);
	const ext = extname(base).toLowerCase();
	return (ext === ".ovpn" || ext === ".opvn" ? base.slice(0, -ext.length) : base) || "vpn";
}

/** Format milliseconds as H:MM:SS or M:SS. */
export function fmtElapsed(ms: number): string {
	const totalSec = Math.max(0, Math.floor(ms / 1000));
	const h = Math.floor(totalSec / 3600);
	const m = Math.floor((totalSec % 3600) / 60);
	const s = totalSec % 60;
	const pad = (n: number) => String(n).padStart(2, "0");
	return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

export function slugify(name: string): string {
	return name.replace(/[^a-z0-9_-]+/gi, "_").slice(0, 40) || "vpn";
}

/** Does an OpenVPN config require interactive username/password auth? */
export function configNeedsAuth(configPath: string): boolean {
	try {
		const text = readFileSync(configPath, "utf8").replace(/\r/g, "");
		return /^\s*auth-user-pass\s*$/m.test(text);
	} catch {
		return false;
	}
}

/** Is a process alive? Works for root-owned PIDs too (EPERM == exists). */
export function pidAlive(pid: number | null): boolean {
	if (!pid) return false;
	try {
		process.kill(pid, 0);
		return true;
	} catch (e) {
		return (e as NodeJS.ErrnoException).code === "EPERM";
	}
}

export function readPid(pidFile: string): number | null {
	try {
		const t = readFileSync(pidFile, "utf8").trim();
		const n = Number(t);
		return Number.isFinite(n) && n > 0 ? n : null;
	} catch {
		return null;
	}
}

// ---------------------------------------------------------------------------
// Network inspection (no root needed)
// ---------------------------------------------------------------------------

export interface TunnelIface {
	dev: string;
	ip: string;
}

/** Find the first tun/tap interface with an IPv4 address. Optionally filter by dev. */
export function getTunnelIface(dev?: string | null): TunnelIface | null {
	// JSON output first (iproute2 >= 4.0).
	try {
		const r = spawnSync("ip", ["-j", "-4", "addr", "show"], { encoding: "utf8", timeout: 5000 });
		if (r.status === 0 && r.stdout) {
			const ifaces = JSON.parse(r.stdout) as Array<{
				ifname: string;
				addr_info?: Array<{ local?: string; inet?: string; address?: string }>;
			}>;
			for (const iface of ifaces) {
				const n = iface.ifname || "";
				if (!/^(tun|tap|ppp|ovpn)/.test(n)) continue;
				if (dev && n !== dev) continue;
				const a = iface.addr_info?.find((x) => x.local || x.inet || x.address);
				const ip = (a?.local || a?.inet || a?.address || "").split("/")[0];
				if (ip) return { dev: n, ip };
			}
		}
	} catch {
		/* fall through */
	}
	// Fallback: text parse.
	try {
		const r = spawnSync("ip", ["-4", "addr", "show"], { encoding: "utf8", timeout: 5000 });
		if (r.status === 0 && r.stdout) {
			let curDev = "";
			for (const line of r.stdout.split("\n")) {
				const m = line.match(/^\d+:\s+([^:@]+)/);
				if (m) {
					curDev = m[1].trim();
					continue;
				}
				const inet = line.match(/inet\s+([\d.]+)/);
				if (inet && /^(tun|tap|ppp|ovpn)/.test(curDev) && (!dev || curDev === dev)) {
					return { dev: curDev, ip: inet[1] };
				}
			}
		}
	} catch {
		/* ignore */
	}
	return null;
}

// ---------------------------------------------------------------------------
// .ovpn discovery
// ---------------------------------------------------------------------------

/** Default directories scanned for .ovpn/.opvn files. */
export function defaultSearchDirs(cwd: string): string[] {
	return [
		cwd,
		join(homedir(), "ctf"),
		join(homedir(), "Downloads"),
		join(homedir(), "hackerone"),
		join(homedir(), "security"),
		homedir(),
	];
}

/** Find .ovpn/.opvn files under the given directories (non-recursive, top-level only). */
export function findOvpnFiles(dirs: string[]): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const dir of dirs) {
		let entries: string[] = [];
		try {
			entries = readdirSync(dir);
		} catch {
			continue;
		}
		for (const entry of entries) {
			const lower = entry.toLowerCase();
			if (lower.endsWith(".ovpn") || lower.endsWith(".opvn")) {
				const full = join(dir, entry);
				try {
					if (statSync(full).isFile()) {
						const real = resolve(full);
						if (!seen.has(real)) {
							seen.add(real);
							out.push(real);
						}
					}
				} catch {
					/* ignore */
				}
			}
		}
	}
	return out.sort();
}

// ---------------------------------------------------------------------------
// Privilege model
// ---------------------------------------------------------------------------

export function runPrivileged(args: string[], opts?: { input?: string; timeout?: number }) {
	if (isRoot()) {
		return spawnSync("openvpn", args, {
			input: opts?.input,
			timeout: opts?.timeout ?? 30_000,
			encoding: "utf8",
			maxBuffer: 16 * 1024 * 1024,
		});
	}
	return spawnSync("sudo", ["-n", "openvpn", ...args], {
		input: opts?.input,
		timeout: opts?.timeout ?? 30_000,
		encoding: "utf8",
		maxBuffer: 16 * 1024 * 1024,
	});
}

export function killPid(pid: number): boolean {
	if (!pid) return false;
	if (isRoot()) {
		try {
			process.kill(pid, "SIGTERM");
			return true;
		} catch {
			return false;
		}
	}
	const r = spawnSync("sudo", ["-n", "kill", String(pid)], { timeout: 8000 });
	return r.status === 0;
}

/**
 * Ensure we can run privileged commands. Tries, in order: root → passwordless
 * sudo → cached password → `$PI_VPN_SUDO_PASS` → UI prompt (cached in memory
 * only, never written to disk). Returns true if `sudo -n` now works.
 */
export class Sudo {
	private password: string | null = null;
	private knownGood = false;

	constructor() {
		if (process.env.PI_VPN_SUDO_PASS) this.password = process.env.PI_VPN_SUDO_PASS;
	}

	isRoot(): boolean {
		return isRoot();
	}

	/** Refresh the sudo timestamp with the cached password. */
	private refresh(): { ok: boolean; error?: string } {
		if (isRoot()) return { ok: true };
		const cached = spawnSync("sudo", ["-n", "-v"], { timeout: 8000 });
		if (cached.status === 0) {
			this.knownGood = true;
			return { ok: true };
		}
		if (this.password === null) return { ok: false, error: "sudo password required" };
		const r = spawnSync("sudo", ["-S", "-p", "", "-v"], {
			input: this.password + "\n",
			timeout: 8000,
		});
		if (r.status === 0) {
			this.knownGood = true;
			return { ok: true };
		}
		this.password = null;
		this.knownGood = false;
		return { ok: false, error: "sudo authentication failed (wrong password?)" };
	}

	async ensure(ui: UiAdapter): Promise<{ ok: boolean; error?: string }> {
		if (isRoot()) return { ok: true };
		if (this.knownGood) return this.refresh();
		if (spawnSync("sudo", ["-n", "true"], { timeout: 5000 }).status === 0) {
			this.knownGood = true;
			return { ok: true };
		}
		if (this.password === null) {
			const pw = await ui.prompt("sudo password (for openvpn)", { secret: true });
			if (pw === undefined || pw === "") return { ok: false, error: "sudo password required" };
			this.password = pw;
		}
		return this.refresh();
	}

	/** Forget the cached password. */
	forget(): void {
		this.password = null;
		this.knownGood = false;
	}
}

// ---------------------------------------------------------------------------
// Log parsing
// ---------------------------------------------------------------------------

export function parseDev(log: string): string | null {
	const m = log.match(/TUN\/TAP device (\S+) opened/);
	return m ? m[1] : null;
}

export function matchFailure(log: string): string | null {
	if (!log) return null;
	if (/AUTH_FAILED/i.test(log)) return "authentication failed (check VPN credentials)";
	if (/private key password verification failed/i.test(log)) return "private key password rejected";
	if (/Options error:/i.test(log)) {
		const m = log.match(/Options error:(.*)/i);
		return m ? `config error:${m[1].split("\n")[0]}` : "config error";
	}
	if (/Exiting due to fatal error/i.test(log)) return tailFrom(log, "Exiting due to fatal error") || "fatal error";
	if (/Cannot ioctl TUNSETIFF/i.test(log)) return "cannot create tun device (already connected / no privileges)";
	if (/Inactivity timeout/i.test(log)) return "inactivity timeout";
	return null;
}

function tailFrom(log: string, marker: string): string | null {
	const idx = log.lastIndexOf(marker);
	if (idx < 0) return null;
	return log
		.slice(idx)
		.split("\n")
		.slice(0, 3)
		.join(" ")
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, 300);
}

export function tailError(logFile: string): string | null {
	try {
		const text = readFileSync(logFile, "utf8");
		const lines = text.split("\n").filter((l) => /error|fail|fatal|exit/i.test(l));
		return lines.slice(-3).join(" ").replace(/\s+/g, " ").trim().slice(0, 300) || null;
	} catch {
		return null;
	}
}

/** Read the last `n` lines of a log file (best-effort). */
export function tailLog(logFile: string, n: number): string[] {
	try {
		const text = readFileSync(logFile, "utf8");
		return text.split("\n").filter((l) => l.trim().length > 0).slice(-n);
	} catch {
		return [];
	}
}

// ---------------------------------------------------------------------------
// Auth file
// ---------------------------------------------------------------------------

export function writeAuthFile(username: string, password: string): string {
	const rand = Math.random().toString(36).slice(2, 10);
	const file = join(DATA_DIR, `auth-${rand}.txt`);
	writeFileSync(file, `${username}\n${password}\n`, { mode: 0o600 });
	return file;
}

// ---------------------------------------------------------------------------
// VPN manager
// ---------------------------------------------------------------------------

function blankState(): VpnInfo {
	return {
		name: "",
		configPath: "",
		status: "disconnected",
		ip: null,
		dev: null,
		pid: null,
		startTime: null,
		connectTime: null,
		error: null,
	};
}

export class VpnManager {
	public state: VpnInfo = blankState();
	private sudo = new Sudo();

	constructor() {
		ensureDirs();
	}

	snapshot(): VpnInfo {
		return { ...this.state };
	}

	/** Refresh the live IP from the kernel (no root). */
	refreshIp(): void {
		if (this.state.status === "connected") {
			const iface = getTunnelIface(this.state.dev);
			if (iface) this.state.ip = iface.ip;
		}
	}

	/** Reattach to a tunnel left over from a previous run. Returns true if attached. */
	reattach(): boolean {
		const p = this.loadPersisted();
		if (!p || !p.pid) {
			this.state = blankState();
			return false;
		}
		if (!pidAlive(p.pid)) {
			this.state = blankState();
			try {
				rmSync(STATE_FILE, { force: true });
			} catch {
				/* ignore */
			}
			return false;
		}
		const iface = getTunnelIface(p.dev);
		this.state = {
			name: p.name,
			configPath: p.configPath,
			status: "connected",
			ip: iface?.ip ?? null,
			dev: iface?.dev ?? p.dev ?? null,
			pid: p.pid,
			startTime: p.startTime ?? Date.now(),
			connectTime: null,
			error: null,
		};
		return true;
	}

	private persist(): void {
		if (this.state.status !== "connected") {
			try {
				rmSync(STATE_FILE, { force: true });
			} catch {
				/* ignore */
			}
			return;
		}
		const data: PersistedState = {
			name: this.state.name,
			configPath: this.state.configPath,
			pid: this.state.pid,
			startTime: this.state.startTime,
			dev: this.state.dev,
		};
		try {
			writeFileSync(STATE_FILE, JSON.stringify(data, null, 2), { mode: 0o600 });
		} catch {
			/* ignore */
		}
	}

	private loadPersisted(): PersistedState | null {
		try {
			return JSON.parse(readFileSync(STATE_FILE, "utf8")) as PersistedState;
		} catch {
			return null;
		}
	}

	async connect(
		ui: UiAdapter,
		opts: ConnectOptions,
		cwd: string,
		signal?: AbortSignal,
	): Promise<VpnInfo> {
		const configPath = resolve(cwd, opts.configPath);
		if (!existsSync(configPath)) throw new Error(`Config not found: ${configPath}`);
		const name = opts.name || nameFromPath(configPath);

		// Tear down anything currently up.
		if (this.state.status === "connected" || this.state.status === "connecting") {
			await this.disconnect();
		}

		// Credentials.
		let authFile: string | null = null;
		let ownsAuthFile = false;
		const needsAuth = configNeedsAuth(configPath);
		if (opts.authFile) {
			authFile = resolve(cwd, opts.authFile);
		} else if (opts.username || opts.password) {
			authFile = writeAuthFile(opts.username || "", opts.password || "");
			ownsAuthFile = true;
		} else if (needsAuth) {
			const username = await ui.prompt("VPN username");
			if (username === undefined) throw new Error("cancelled");
			const password = await ui.prompt("VPN password", { secret: true });
			if (password === undefined) throw new Error("cancelled");
			authFile = writeAuthFile(username, password);
			ownsAuthFile = true;
		}

		// Privileges.
		const sudo = await this.sudo.ensure(ui);
		if (!sudo.ok) throw new Error(sudo.error || "sudo required to run openvpn");

		const slug = slugify(name);
		const logFile = join(LOG_DIR, `${slug}.log`);
		const pidFile = join(PID_DIR, `${slug}.pid`);
		try {
			rmSync(logFile, { force: true });
		} catch {
			/* ignore */
		}

		const args = [
			"--config",
			configPath,
			"--daemon",
			`ovpn-pi-${slug}`,
			"--writepid",
			pidFile,
			"--log",
			logFile,
		];
		if (authFile) args.push("--auth-user-pass", authFile);

		this.state = {
			name,
			configPath,
			status: "connecting",
			connectTime: Date.now(),
			startTime: null,
			ip: null,
			dev: null,
			pid: null,
			error: null,
		};

		try {
			const start = runPrivileged(args, { timeout: 20_000 });
			if (start.status !== 0) {
				const msg = (start.stderr || start.stdout || "").trim().slice(0, 500);
				throw new Error(`openvpn failed to start${msg ? `: ${msg}` : ""}`);
			}
			const result = await monitorLog(logFile, pidFile, signal);
			if (result.kind === "success") {
				const iface = getTunnelIface(result.dev);
				this.state = {
					...this.state,
					status: "connected",
					startTime: Date.now(),
					ip: iface?.ip ?? null,
					dev: iface?.dev ?? result.dev ?? null,
					pid: result.pid,
				};
				this.persist();
				return this.snapshot();
			}
			if (result.pid) killPid(result.pid);
			throw new Error(result.reason || "openvpn failed to connect");
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			this.state = { ...this.state, status: "error", error: message, connectTime: null };
			try {
				rmSync(pidFile, { force: true });
			} catch {
				/* ignore */
			}
			throw err;
		} finally {
			if (ownsAuthFile && authFile) {
				try {
					rmSync(authFile, { force: true });
				} catch {
					/* ignore */
				}
			}
		}
	}

	async disconnect(): Promise<VpnInfo> {
		const pid =
			this.state.pid ??
			readPid(join(PID_DIR, `${slugify(this.state.name || "vpn")}.pid`));
		if (pid) killPid(pid);
		const name = this.state.name;
		this.state = blankState();
		try {
			rmSync(STATE_FILE, { force: true });
		} catch {
			/* ignore */
		}
		void name;
		return this.snapshot();
	}

	/** Path to the log file for the current (or last) connection. */
	currentLogFile(): string | null {
		const name = this.state.name || this.loadPersisted()?.name;
		if (!name) return null;
		return join(LOG_DIR, `${slugify(name)}.log`);
	}
}

// ---------------------------------------------------------------------------
// Log monitor (module-level: also usable standalone)
// ---------------------------------------------------------------------------

interface MonitorResult {
	kind: "success" | "fail";
	pid: number | null;
	dev: string | null;
	reason?: string;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
	return new Promise((res, rej) => {
		const t = setTimeout(res, ms);
		signal?.addEventListener(
			"abort",
			() => {
				clearTimeout(t);
				rej(new Error("aborted"));
			},
			{ once: true },
		);
	});
}

export async function monitorLog(
	logFile: string,
	pidFile: string,
	signal?: AbortSignal,
): Promise<MonitorResult> {
	const deadline = Date.now() + MONITOR_TIMEOUT_MS;
	let lastSize = 0;
	let pid: number | null = null;

	while (Date.now() < deadline) {
		if (signal?.aborted) return { kind: "fail", pid, dev: null, reason: "cancelled" };
		await sleep(MONITOR_INTERVAL_MS, signal).catch(() => {});

		let text = "";
		try {
			const st = statSync(logFile);
			if (st.size < lastSize) lastSize = 0;
			const fd = readFileSync(logFile);
			text = fd.toString("utf8", lastSize);
			lastSize = fd.length;
		} catch {
			text = "";
		}

		pid = pid ?? readPid(pidFile);

		if (text) {
			if (/Initialization Sequence Completed/.test(text)) {
				return { kind: "success", pid, dev: parseDev(text) };
			}
			const fail = matchFailure(text);
			if (fail) return { kind: "fail", pid, dev: null, reason: fail };
		}

		if (pid !== null && !pidAlive(pid)) {
			const reason = matchFailure(text) || tailError(logFile) || "openvpn process exited";
			return { kind: "fail", pid, dev: null, reason };
		}
	}
	return { kind: "fail", pid, dev: null, reason: "connection timed out" };
}
