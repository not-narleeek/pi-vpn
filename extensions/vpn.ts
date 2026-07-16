/**
 * VPN (OpenVPN) extension for pi.
 *
 * Connect to an OpenVPN server from a `.ovpn` / `.opvn` config file with a
 * single command or tool call, and keep a live status line in the footer
 * showing: connection name, status, assigned VPN IP, and elapsed time.
 *
 * Built for CTF / bug-bounty workflows where you spin up lab VPNs often.
 *
 * Usage:
 *   /vpn                       interactive status panel
 *   /vpn connect <file.ovpn>   connect (prompts for creds if the profile needs them)
 *   /vpn disconnect            tear the current tunnel down
 *   /vpn status                one-line status notification
 *   /vpn list                  pick an .ovpn from common directories
 *
 *   The agent can also use the vpn_connect / vpn_disconnect / vpn_status /
 *   vpn_list tools directly.
 *
 * Privilege model:
 *   openvpn needs root. The extension uses:
 *     1. root directly if pi is already running as root
 *     2. passwordless `sudo -n` if available
 *     3. the PI_VPN_SUDO_PASS env var
 *     4. an in-session prompt (cached only in memory, never written to disk)
 *
 * The tunnel is started with `openvpn --daemon` so it SURVIVES pi quitting,
 * which is what you want during a long CTF. Disconnect explicitly with
 * `/vpn disconnect`.
 */

import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI, ExtensionContext, Theme } from "@earendil-works/pi-coding-agent";
import { matchesKey, Text, truncateToWidth } from "@earendil-works/pi-tui";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, extname, join, resolve } from "node:path";
import { Type } from "typebox";

// ---------------------------------------------------------------------------
// Constants & pure helpers
// ---------------------------------------------------------------------------

const DATA_DIR = join(homedir(), ".pi", "vpn");
const LOG_DIR = join(DATA_DIR, "logs");
const PID_DIR = join(DATA_DIR, "pid");
const STATE_FILE = join(DATA_DIR, "state.json");

const MONITOR_TIMEOUT_MS = 60_000;
const MONITOR_INTERVAL_MS = 500;

type Status = "disconnected" | "connecting" | "connected" | "error";

interface VpnInfo {
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

interface PersistedState {
	name: string;
	configPath: string;
	pid: number | null;
	startTime: number | null;
	dev: string | null;
}

function ensureDirs(): void {
	mkdirSync(LOG_DIR, { recursive: true });
	mkdirSync(PID_DIR, { recursive: true });
}

function isRoot(): boolean {
	return typeof process.getuid === "function" && process.getuid() === 0;
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

/** Format milliseconds as H:MM:SS or M:SS. */
export function fmtElapsed(ms: number): string {
	const totalSec = Math.max(0, Math.floor(ms / 1000));
	const h = Math.floor(totalSec / 3600);
	const m = Math.floor((totalSec % 3600) / 60);
	const s = totalSec % 60;
	const pad = (n: number) => String(n).padStart(2, "0");
	return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

/** Is a process alive? Works for root-owned PIDs too (EPERM == exists). */
function pidAlive(pid: number | null): boolean {
	if (!pid) return false;
	try {
		process.kill(pid, 0);
		return true;
	} catch (e) {
		return (e as NodeJS.ErrnoException).code === "EPERM";
	}
}

/** Derive a friendly connection name from a config file path. */
export function nameFromPath(configPath: string): string {
	const base = basename(configPath);
	const ext = extname(base).toLowerCase();
	return (ext === ".ovpn" || ext === ".opvn" ? base.slice(0, -ext.length) : base) || "vpn";
}

/** Does an OpenVPN config require interactive username/password auth? */
export function configNeedsAuth(configPath: string): boolean {
	try {
		const text = readFileSync(configPath, "utf8").replace(/\r/g, "");
		// a bare "auth-user-pass" with no file argument means it will prompt
		return /^\s*auth-user-pass\s*$/m.test(text);
	} catch {
		return false;
	}
}

// ---------------------------------------------------------------------------
// Network inspection (no root needed)
// ---------------------------------------------------------------------------

interface TunnelIface {
	dev: string;
	ip: string;
}

/** Find the first tun/tap interface with an IPv4 address. Optionally filter by dev. */
function getTunnelIface(dev?: string | null): TunnelIface | null {
	// Try JSON output first (iproute2 >= 4.0).
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
		/* fall through to text parse */
	}

	// Fallback: text parse of `ip -4 addr`.
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
// Status panel component (used by /vpn)
// ---------------------------------------------------------------------------

class VpnPanel {
	private info: VpnInfo;
	private theme: Theme;
	private onClose: (action: string) => void;
	private tui?: { requestRender(force?: boolean): void };
	private cachedWidth?: number;
	private cachedLines?: string[];

	constructor(info: VpnInfo, theme: Theme, onClose: (action: string) => void) {
		this.info = info;
		this.theme = theme;
		this.onClose = onClose;
	}

	setTui(tui: { requestRender(force?: boolean): void }): void {
		this.tui = tui;
	}

	update(info: VpnInfo): void {
		this.info = info;
		this.cachedWidth = undefined;
		this.tui?.requestRender();
	}

	handleInput(data: string): void {
		if (matchesKey(data, "escape") || matchesKey(data, "ctrl+c") || matchesKey(data, "q")) {
			this.onClose("close");
		} else if (matchesKey(data, "d")) {
			this.onClose("disconnect");
		} else if (matchesKey(data, "l")) {
			this.onClose("list");
		} else if (matchesKey(data, "r")) {
			this.cachedWidth = undefined;
			this.tui?.requestRender();
		}
	}

	render(width: number): string[] {
		if (this.cachedLines && this.cachedWidth === width) return this.cachedLines;
		const th = this.theme;
		const i = this.info;
		const lines: string[] = [];

		const title = th.fg("accent", th.bold("  VPN Status  "));
		const bar = th.fg("borderMuted", "─".repeat(Math.max(2, Math.floor((width - 16) / 2))));
		lines.push(truncateToWidth(`${bar}${title}${th.fg("borderMuted", "─".repeat(width))}`, width));
		lines.push("");

		const row = (label: string, value: string) =>
			truncateToWidth(`  ${th.fg("muted", label.padEnd(10))} ${value}`, width);

		const statusBadge = (s: Status): string => {
			switch (s) {
				case "connected":
					return th.fg("success", "● connected");
				case "connecting":
					return th.fg("warning", "◌ connecting");
				case "error":
					return th.fg("error", "✖ error");
				default:
					return th.fg("dim", "○ disconnected");
			}
		};

		lines.push(row("Name", i.name ? th.fg("text", i.name) : th.fg("dim", "—")));
		lines.push(row("Status", statusBadge(i.status)));

		let elapsed = "—";
		if (i.status === "connected" && i.startTime) {
			elapsed = th.fg("accent", fmtElapsed(Date.now() - i.startTime));
		} else if (i.status === "connecting" && i.connectTime) {
			elapsed = th.fg("dim", `${Math.floor((Date.now() - i.connectTime) / 1000)}s`);
		}
		lines.push(row("Elapsed", elapsed));
		lines.push(row("VPN IP", i.ip ? th.fg("success", i.ip) : th.fg("dim", "—")));
		lines.push(row("Device", i.dev ? th.fg("muted", i.dev) : th.fg("dim", "—")));
		lines.push(row("PID", i.pid ? th.fg("dim", String(i.pid)) : th.fg("dim", "—")));
		lines.push(
			row(
				"Config",
				i.configPath ? truncateToWidth(th.fg("dim", i.configPath), Math.max(10, width - 14)) : th.fg("dim", "—"),
			),
		);

		if (i.error) {
			lines.push("");
			lines.push(truncateToWidth(`  ${th.fg("error", "✖ " + i.error)}`, width));
		}

		lines.push("");
		const hint = (k: string, d: string) => `${th.fg("accent", k)}${th.fg("dim", ` ${d}  `)}`;
		lines.push(
			truncateToWidth(
				"  " + hint("d", "disconnect") + hint("l", "list/connect") + hint("r", "refresh") + hint("q", "close"),
				width,
			),
		);
		lines.push("");

		this.cachedWidth = width;
		this.cachedLines = lines;
		return lines;
	}

	invalidate(): void {
		this.cachedWidth = undefined;
	}
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

export default function vpnExtension(pi: ExtensionAPI) {
	ensureDirs();

	// ---- session-scoped state -------------------------------------------------
	let state: VpnInfo = blankState();
	let timer: ReturnType<typeof setInterval> | null = null;
	let panel: VpnPanel | null = null;
	// sudo password cached only in memory for the lifetime of this process
	let sudoPassword: string | null = null;
	let sudoKnownGood = false;

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

	// ---- persistence ----------------------------------------------------------

	function persist(): void {
		if (state.status !== "connected") {
			try {
				rmSync(STATE_FILE, { force: true });
			} catch {
				/* ignore */
			}
			return;
		}
		const data: PersistedState = {
			name: state.name,
			configPath: state.configPath,
			pid: state.pid,
			startTime: state.startTime,
			dev: state.dev,
		};
		try {
			writeFileSync(STATE_FILE, JSON.stringify(data, null, 2), { mode: 0o600 });
		} catch {
			/* ignore */
		}
	}

	function loadPersisted(): PersistedState | null {
		try {
			const raw = readFileSync(STATE_FILE, "utf8");
			return JSON.parse(raw) as PersistedState;
		} catch {
			return null;
		}
	}

	// ---- sudo / privileged execution -----------------------------------------

	function runPrivileged(args: string[], opts?: { input?: string; timeout?: number }) {
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

	/** Refresh / acquire sudo credentials. Returns true if `sudo -n` now works. */
	function refreshSudo(): { ok: boolean; error?: string } {
		if (isRoot()) return { ok: true };
		// already cached this session?
		const cached = spawnSync("sudo", ["-n", "-v"], { timeout: 8000 });
		if (cached.status === 0) {
			sudoKnownGood = true;
			return { ok: true };
		}
		if (sudoPassword === null) return { ok: false, error: "sudo password required" };
		const r = spawnSync("sudo", ["-S", "-p", "", "-v"], { input: sudoPassword + "\n", timeout: 8000 });
		if (r.status === 0) {
			sudoKnownGood = true;
			return { ok: true };
		}
		sudoPassword = null;
		sudoKnownGood = false;
		return { ok: false, error: "sudo authentication failed (wrong password?)" };
	}

	/** Ensure we can run privileged commands, prompting via UI if necessary. */
	async function ensureSudo(ctx: ExtensionContext): Promise<{ ok: boolean; error?: string }> {
		if (isRoot()) return { ok: true };
		if (sudoKnownGood) return refreshSudo();
		// passwordless?
		if (spawnSync("sudo", ["-n", "true"], { timeout: 5000 }).status === 0) {
			sudoKnownGood = true;
			return { ok: true };
		}
		// env var?
		if (process.env.PI_VPN_SUDO_PASS) sudoPassword = process.env.PI_VPN_SUDO_PASS;
		if (sudoPassword === null && ctx.hasUI) {
			const pw = await ctx.ui.input("sudo password", "openvpn needs root (not masked)");
			if (pw === undefined || pw === "") return { ok: false, error: "sudo password required" };
			sudoPassword = pw;
		}
		if (sudoPassword === null) return { ok: false, error: "sudo password required" };
		return refreshSudo();
	}

	/** Kill a PID (root-owned tunnels need sudo). */
	function killPid(pid: number): boolean {
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

	// ---- UI rendering ---------------------------------------------------------

	function infoSnapshot(): VpnInfo {
		return { ...state, ip: state.ip };
	}

	function renderFooter(ctx: ExtensionContext): void {
		if (!ctx.hasUI) return;
		const th = ctx.ui.theme;
		const i = state;
		let text: string;
		if (i.status === "disconnected") {
			text = th.fg("dim", "🔒 vpn off");
		} else if (i.status === "connecting") {
			const secs = i.connectTime ? Math.floor((Date.now() - i.connectTime) / 1000) : 0;
			text = th.fg("warning", "◌ ") + th.fg("muted", `${i.name} · connecting ${secs}s`);
		} else if (i.status === "error") {
			text = th.fg("error", "✖ ") + th.fg("muted", `${i.name} · error`);
		} else {
			const elapsed = i.startTime ? fmtElapsed(Date.now() - i.startTime) : "0:00";
			const ip = i.ip ?? "—";
			text =
				th.fg("success", "🔒 ") +
				th.fg("text", i.name) +
				th.fg("dim", " · ") +
				th.fg("success", "●") +
				th.fg("dim", " · ") +
				th.fg("accent", ip) +
				th.fg("dim", " · ") +
				th.fg("muted", elapsed);
		}
		ctx.ui.setStatus("vpn", text);
		panel?.update(infoSnapshot());
	}

	function clearFooter(ctx: ExtensionContext): void {
		if (!ctx.hasUI) return;
		ctx.ui.setStatus("vpn", undefined);
	}

	function startTimer(ctx: ExtensionContext): void {
		stopTimer();
		timer = setInterval(() => renderFooter(ctx), 1000);
	}

	function stopTimer(): void {
		if (timer) {
			clearInterval(timer);
			timer = null;
		}
	}

	function setState(patch: Partial<VpnInfo>, ctx?: ExtensionContext): void {
		state = { ...state, ...patch };
		if (ctx) renderFooter(ctx);
		if (state.status === "connected") persist();
	}

	// ---- auth file ------------------------------------------------------------

	function writeAuthFile(username: string, password: string): string {
		const rand = Math.random().toString(36).slice(2, 10);
		const file = join(DATA_DIR, `auth-${rand}.txt`);
		writeFileSync(file, `${username}\n${password}\n`, { mode: 0o600 });
		return file;
	}

	// ---- connect / disconnect core -------------------------------------------

	async function connectVPN(
		ctx: ExtensionContext,
		opts: { configPath: string; name?: string; username?: string; password?: string; authFile?: string },
		signal?: AbortSignal,
	): Promise<VpnInfo> {
		const configPath = resolve(ctx.cwd, opts.configPath);
		if (!existsSync(configPath)) throw new Error(`Config not found: ${configPath}`);
		const name = opts.name || nameFromPath(configPath);

		// If something is already up, tear it down first.
		if (state.status === "connected" || state.status === "connecting") {
			await disconnectVPN(ctx, /*silent*/ true);
		}

		// Credentials handling.
		let authFile: string | null = null;
		let ownsAuthFile = false;
		const needsAuth = configNeedsAuth(configPath);
		if (opts.authFile) {
			authFile = resolve(ctx.cwd, opts.authFile);
		} else if (opts.username || opts.password) {
			authFile = writeAuthFile(opts.username || "", opts.password || "");
			ownsAuthFile = true;
		} else if (needsAuth) {
			// Prompt interactively when running through the UI.
			if (ctx.hasUI) {
				const username = await ctx.ui.input("VPN username", "");
				if (username === undefined) throw new Error("cancelled");
				const password = await ctx.ui.input("VPN password", "(not masked)");
				if (password === undefined) throw new Error("cancelled");
				authFile = writeAuthFile(username, password);
				ownsAuthFile = true;
			} else {
				throw new Error(
					"This profile requires a username/password. Provide username/password or an auth file.",
				);
			}
		}

		// Privileges.
		const sudo = await ensureSudo(ctx);
		if (!sudo.ok) throw new Error(sudo.error || "sudo required to run openvpn");

		// Prep runtime files.
		const slug = name.replace(/[^a-z0-9_-]+/gi, "_").slice(0, 40) || "vpn";
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
		if (authFile) {
			args.push("--auth-user-pass", authFile);
		}

		setState(
			{
				name,
				configPath,
				status: "connecting",
				connectTime: Date.now(),
				startTime: null,
				ip: null,
				dev: null,
				pid: null,
				error: null,
			},
			ctx,
		);
		startTimer(ctx);

		try {
			const start = runPrivileged(args, { timeout: 20_000 });
			if (start.status !== 0) {
				const msg = (start.stderr || start.stdout || "").trim().slice(0, 500);
				throw new Error(`openvpn failed to start${msg ? `: ${msg}` : ""}`);
			}

			// Monitor the log until success, fatal error, or timeout.
			const result = await monitorLog(logFile, pidFile, signal);
			if (result.kind === "success") {
				const iface = getTunnelIface(result.dev);
				setState(
					{
						status: "connected",
						startTime: Date.now(),
						ip: iface?.ip ?? null,
						dev: iface?.dev ?? result.dev ?? null,
						pid: result.pid,
					},
					ctx,
				);
				if (ctx.hasUI) ctx.ui.notify(`Connected to ${name}${iface ? ` (${iface.ip})` : ""}`, "info");
				return infoSnapshot();
			}
			// failure
			killPid(result.pid);
			throw new Error(result.reason || "openvpn failed to connect");
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			stopTimer();
			setState({ status: "error", error: message, connectTime: null }, ctx);
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

	interface MonitorResult {
		kind: "success" | "fail";
		pid: number | null;
		dev: string | null;
		reason?: string;
	}

	function readPid(pidFile: string): number | null {
		try {
			const t = readFileSync(pidFile, "utf8").trim();
			const n = Number(t);
			return Number.isFinite(n) && n > 0 ? n : null;
		} catch {
			return null;
		}
	}

	async function monitorLog(logFile: string, pidFile: string, signal?: AbortSignal): Promise<MonitorResult> {
		const deadline = Date.now() + MONITOR_TIMEOUT_MS;
		let lastSize = 0;
		let pid: number | null = null;

		while (Date.now() < deadline) {
			if (signal?.aborted) return { kind: "fail", pid, dev: null, reason: "cancelled" };
			await sleep(MONITOR_INTERVAL_MS, signal).catch(() => {});

			let text = "";
			try {
				const st = statSync(logFile);
				if (st.size < lastSize) lastSize = 0; // rotated/truncated
				const fd = readFileSync(logFile);
				text = fd.toString("utf8", lastSize);
				lastSize = fd.length;
			} catch {
				text = "";
			}

			pid = pid ?? readPid(pidFile);

			if (text) {
				if (/Initialization Sequence Completed/.test(text)) {
					const dev = parseDev(text);
					return { kind: "success", pid, dev };
				}
				const fail = matchFailure(text);
				if (fail) return { kind: "fail", pid, dev: null, reason: fail };
			}

			// process died before success
			if (pid !== null && !pidAlive(pid)) {
				const reason = matchFailure(text) || tailError(logFile) || "openvpn process exited";
				return { kind: "fail", pid, dev: null, reason };
			}
		}
		return { kind: "fail", pid, dev: null, reason: "connection timed out" };
	}

	function parseDev(log: string): string | null {
		const m = log.match(/TUN\/TAP device (\S+) opened/);
		return m ? m[1] : null;
	}

	function matchFailure(log: string): string | null {
		if (!log) return null;
		if (/AUTH_FAILED/i.test(log)) return "authentication failed (check VPN credentials)";
		if (/private key password verification failed/i.test(log)) return "private key password rejected";
		if (/Options error:/i.test(log)) {
			const m = log.match(/Options error:(.*)/i);
			return m ? `config error:${m[1].split("\n")[0]}` : "config error";
		}
		if (/Exiting due to fatal error/i.test(log)) {
			return tailFrom(log, "Exiting due to fatal error") || "fatal error";
		}
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

	function tailError(logFile: string): string | null {
		try {
			const text = readFileSync(logFile, "utf8");
			const lines = text.split("\n").filter((l) => /error|fail|fatal|exit/i.test(l));
			return lines.slice(-3).join(" ").replace(/\s+/g, " ").trim().slice(0, 300) || null;
		} catch {
			return null;
		}
	}

	async function disconnectVPN(ctx: ExtensionContext, silent = false): Promise<VpnInfo> {
		stopTimer();
		const pid = state.pid ?? readPid(join(PID_DIR, `${(state.name || "vpn").replace(/[^a-z0-9_-]+/gi, "_").slice(0, 40) || "vpn"}.pid`));
		const wasConnected = state.status === "connected" || state.status === "connecting";
		const name = state.name;
		if (pid) killPid(pid);
		setState({ ...blankState() }, ctx);
		try {
			rmSync(STATE_FILE, { force: true });
		} catch {
			/* ignore */
		}
		if (wasConnected && ctx.hasUI && !silent) {
			ctx.ui.notify(`Disconnected from ${name || "VPN"}`, "info");
		}
		renderFooter(ctx);
		return infoSnapshot();
	}

	/** Reattach to a tunnel that survived a pi restart. */
	function reattach(ctx: ExtensionContext): void {
		const p = loadPersisted();
		if (!p || !p.pid) {
			state = blankState();
			renderFooter(ctx);
			return;
		}
		if (!pidAlive(p.pid)) {
			state = blankState();
			try {
				rmSync(STATE_FILE, { force: true });
			} catch {
				/* ignore */
			}
			renderFooter(ctx);
			return;
		}
		const iface = getTunnelIface(p.dev);
		state = {
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
		renderFooter(ctx);
		startTimer(ctx);
	}

	// ---- ovpn discovery -------------------------------------------------------

	function findOvpnFiles(): string[] {
		const candidates = [
			ctx_cwd(),
			join(homedir(), "ctf"),
			join(homedir(), "Downloads"),
			join(homedir(), "hackerone"),
			join(homedir(), "security"),
			homedir(),
		];
		const seen = new Set<string>();
		const out: string[] = [];
		for (const dir of candidates) {
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

	// cwd lazily read from the latest context (set on session_start).
	let ctx_cwd = (): string => process.cwd();

	// ---- tools ----------------------------------------------------------------

	const vpnInfoFromState = (): VpnInfo => infoSnapshot();

	pi.registerTool({
		name: "vpn_connect",
		label: "VPN Connect",
		description:
			"Connect to an OpenVPN server from a .ovpn/.opvn config file. Shows a live status line in the footer with the connection name, status, VPN IP, and elapsed time. The tunnel survives pi quitting; disconnect with vpn_disconnect. If the profile needs credentials, pass username/password or authFile.",
		promptSnippet: "Connect to (or switch) an OpenVPN tunnel from a .ovpn config file",
		promptGuidelines: [
			"Use vpn_connect when the user asks to connect to a CTF / lab VPN from an .ovpn file. Pass username/password only if the user provided them; otherwise let the extension prompt.",
			"Use vpn_status to report the current tunnel (name, status, IP, elapsed) and vpn_disconnect to tear it down.",
			"Use vpn_list to discover .ovpn files in the workspace and common directories before asking the user for a path.",
		],
		parameters: Type.Object({
			path: Type.String({ description: "Path to the .ovpn/.opvn config file (absolute or relative to cwd)." }),
			name: Type.Optional(Type.String({ description: "Optional friendly connection name. Defaults to the filename." })),
			username: Type.Optional(Type.String({ description: "VPN username (if the profile requires auth)." })),
			password: Type.Optional(Type.String({ description: "VPN password (if the profile requires auth)." })),
			authFile: Type.Optional(
				Type.String({ description: "Path to an existing auth-user-pass file (username line 1, password line 2)." }),
			),
		}),
		async execute(_id, params, signal, _onUpdate, ctx) {
			try {
				const info = await connectVPN(ctx, params, signal ?? undefined);
				return {
					content: [{ type: "text", text: formatInfo(info) }],
					details: { vpn: info },
				};
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				return {
					content: [{ type: "text", text: `VPN connect failed: ${message}` }],
					details: { vpn: vpnInfoFromState() },
					isError: true,
				};
			}
		},
		renderCall(args, theme) {
			let text = theme.fg("toolTitle", theme.bold("vpn_connect "));
			text += theme.fg("dim", String(args.path ?? ""));
			return new Text(text, 0, 0);
		},
		renderResult(result, { expanded }, theme) {
			const info = (result.details as { vpn?: VpnInfo } | undefined)?.vpn;
			if (!info) return new Text(result.content[0]?.type === "text" ? result.content[0].text : "", 0, 0);
			return new Text(renderInfoText(info, theme, expanded), 0, 0);
		},
	});

	pi.registerTool({
		name: "vpn_disconnect",
		label: "VPN Disconnect",
		description: "Disconnect the current OpenVPN tunnel started by vpn_connect.",
		promptSnippet: "Tear down the current OpenVPN tunnel",
		parameters: Type.Object({}),
		async execute(_id, _params, _signal, _onUpdate, ctx) {
			const info = await disconnectVPN(ctx);
			return { content: [{ type: "text", text: `Disconnected from ${info.name || "VPN"}.` }], details: { vpn: info } };
		},
		renderCall(_args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("vpn_disconnect")), 0, 0);
		},
	});

	pi.registerTool({
		name: "vpn_status",
		label: "VPN Status",
		description:
			"Return the current OpenVPN connection status: name, status, assigned VPN IP, device, PID, and elapsed time.",
		promptSnippet: "Report current OpenVPN tunnel status (name, status, IP, elapsed)",
		parameters: Type.Object({}),
		async execute() {
			// refresh IP live
			if (state.status === "connected") {
				const iface = getTunnelIface(state.dev);
				if (iface) state.ip = iface.ip;
			}
			const info = vpnInfoFromState();
			return { content: [{ type: "text", text: formatInfo(info) }], details: { vpn: info } };
		},
		renderCall(_args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("vpn_status")), 0, 0);
		},
		renderResult(result, { expanded }, theme) {
			const info = (result.details as { vpn?: VpnInfo } | undefined)?.vpn;
			if (!info) return new Text(result.content[0]?.type === "text" ? result.content[0].text : "", 0, 0);
			return new Text(renderInfoText(info, theme, expanded), 0, 0);
		},
	});

	pi.registerTool({
		name: "vpn_list",
		label: "VPN List",
		description: "List .ovpn/.opvn config files found in the workspace and common directories.",
		promptSnippet: "List available .ovpn config files",
		parameters: Type.Object({}),
		async execute() {
			const files = findOvpnFiles();
			const text =
				files.length === 0
					? "No .ovpn/.opvn files found in the workspace or common directories."
					: files.map((f, i) => `${i + 1}. ${f}`).join("\n");
			return { content: [{ type: "text", text }], details: { files } };
		},
		renderCall(_args, theme) {
			return new Text(theme.fg("toolTitle", theme.bold("vpn_list")), 0, 0);
		},
	});

	// ---- shared formatters ----------------------------------------------------

	function formatInfo(i: VpnInfo): string {
		const lines = [
			`name:     ${i.name || "—"}`,
			`status:   ${i.status}`,
			`vpn ip:   ${i.ip ?? "—"}`,
			`device:   ${i.dev ?? "—"}`,
			`pid:      ${i.pid ?? "—"}`,
			`elapsed:  ${i.startTime ? fmtElapsed(Date.now() - i.startTime) : "—"}`,
			`config:   ${i.configPath || "—"}`,
		];
		if (i.error) lines.push(`error:    ${i.error}`);
		return lines.join("\n");
	}

	function renderInfoText(i: VpnInfo, theme: Theme, expanded: boolean): string {
		const th = theme;
		let t =
			th.fg("success", "● ") +
			th.fg("text", i.name || "vpn") +
			th.fg("dim", " — ") +
			th.fg("muted", i.status);
		if (i.ip) t += th.fg("dim", " · ") + th.fg("accent", i.ip);
		if (i.startTime) t += th.fg("dim", " · ") + th.fg("muted", fmtElapsed(Date.now() - i.startTime));
		if (expanded) {
			if (i.dev) t += `\n${th.fg("dim", "device: " + i.dev)}`;
			if (i.pid) t += `\n${th.fg("dim", "pid: " + i.pid)}`;
			if (i.configPath) t += `\n${th.fg("dim", "config: " + i.configPath)}`;
			if (i.error) t += `\n${th.fg("error", i.error)}`;
		}
		return t;
	}

	// ---- /vpn command ---------------------------------------------------------

	pi.registerCommand("vpn", {
		description: "Manage OpenVPN connections: /vpn [connect <file> | disconnect | status | list]",
		getArgumentCompletions(prefix: string) {
			const subs = ["connect", "disconnect", "status", "list"];
			const parts = prefix.split(/\s+/);
			if (parts.length <= 1) {
				const filtered = subs.filter((s) => s.startsWith(prefix));
				return filtered.length > 0 ? filtered.map((s) => ({ value: s, label: s })) : null;
			}
			if (parts[0] === "connect") {
				const files = findOvpnFiles().filter((f) => f.startsWith(prefix));
				return files.length > 0
					? files.map((f) => ({ value: f, label: basename(f), description: f }))
					: null;
			}
			return null;
		},
		handler: async (args, ctx) => {
			ctx_cwd = () => ctx.cwd;
			const trimmed = args.trim();
			const [sub] = trimmed.split(/\s+/);
			const subArgs = trimmed.slice(sub.length).trim();

			if (sub === "connect" || (sub && extname(sub).toLowerCase() === ".ovpn") || extname(sub).toLowerCase() === ".opvn") {
				// Allow both "/vpn connect <file>" and "/vpn <file>"
				let path = subArgs;
				if (sub !== "connect") path = trimmed;
				if (!path) {
					const files = findOvpnFiles();
					if (files.length === 0) {
						ctx.ui.notify("No .ovpn files found. Use: /vpn connect <path>", "warning");
						return;
					}
					const choice = await ctx.ui.select("Pick a config to connect:", files.map((f) => `${basename(f)}  —  ${f}`));
					if (!choice) return;
					path = choice.split("  —  ")[1] || choice;
				}
				const result = await connectVPN(ctx, { configPath: path });
				if (ctx.mode !== "tui") ctx.ui.notify(formatInfo(result), "info");
				return;
			}

			if (sub === "disconnect" || sub === "stop" || sub === "down") {
				await disconnectVPN(ctx);
				return;
			}

			if (sub === "status") {
				if (state.status === "connected") {
					const iface = getTunnelIface(state.dev);
					if (iface) state.ip = iface.ip;
				}
				ctx.ui.notify(formatInfo(infoSnapshot()), "info");
				return;
			}

			if (sub === "list") {
				await runListFlow(ctx);
				return;
			}

			// default: status panel (TUI only)
			if (ctx.mode !== "tui") {
				if (state.status === "connected" && state.dev) {
					const iface = getTunnelIface(state.dev);
					if (iface) state.ip = iface.ip;
				}
				ctx.ui.notify(formatInfo(infoSnapshot()), "info");
				return;
			}

			await runPanel(ctx);
		},
	});

	async function runListFlow(ctx: ExtensionContext): Promise<void> {
		const files = findOvpnFiles();
		if (files.length === 0) {
			ctx.ui.notify("No .ovpn/.opvn files found in the workspace or common dirs.", "warning");
			return;
		}
		const labels = files.map((f) => `${basename(f)}  —  ${f}`);
		const choice = await ctx.ui.select("Pick a config to connect:", labels);
		if (!choice) return;
		const path = choice.split("  —  ")[1] || choice;
		try {
			await connectVPN(ctx, { configPath: path });
		} catch (err) {
			ctx.ui.notify(`VPN connect failed: ${err instanceof Error ? err.message : String(err)}`, "error");
		}
	}

	async function runPanel(ctx: ExtensionContext): Promise<void> {
		if (ctx.mode !== "tui") return;
		let keepOpen = true;
		while (keepOpen) {
			const action = await ctx.ui.custom<string>((tui, theme, _kb, done) => {
				panel = new VpnPanel(infoSnapshot(), theme, (a) => done(a));
				panel.setTui(tui);
				return panel;
			});
			panel = null;
			if (action === "disconnect") {
				try {
					await disconnectVPN(ctx);
				} catch {
					/* ignore */
				}
				continue; // reopen panel
			}
			if (action === "list") {
				await runListFlow(ctx);
				continue;
			}
			keepOpen = false; // close
		}
	}

	// ---- lifecycle ------------------------------------------------------------

	pi.on("session_start", async (_event, ctx) => {
		ctx_cwd = () => ctx.cwd;
		ensureDirs();
		// Reattach to a tunnel that survived a previous pi run.
		reattach(ctx);
		// initial paint (even when disconnected shows the idle indicator)
		renderFooter(ctx);
	});

	pi.on("session_shutdown", async () => {
		// Do NOT kill the tunnel: it is a detached daemon meant to survive pi.
		// Just stop our local timer so it does not leak.
		stopTimer();
		panel = null;
	});
}
