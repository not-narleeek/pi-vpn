#!/usr/bin/env node
/**
 * pi-vpn — standalone terminal UI for OpenVPN.
 *
 * A keyboard-driven, tmux-friendly VPN manager. Discovers .ovpn files, lets
 * you connect/disconnect with a keystroke, shows a live status line and a
 * rolling log, and stays responsive across terminal resizes.
 *
 *   pi-vpn                    launch the TUI (discovers .ovpn files)
 *   pi-vpn <file.ovpn>        launch with a preselected config
 *   pi-vpn connect <file>     non-interactive connect, then exit
 *   pi-vpn disconnect         tear down the current tunnel, then exit
 *   pi-vpn status             one-line status, then exit
 *   pi-vpn list               list discovered .ovpn files
 *
 * All VPN logic lives in ./vpn-core (framework-agnostic). This file is purely
 * rendering + terminal handling + the CLI. Zero runtime npm dependencies.
 *
 * tmux notes: uses the alternate screen buffer (scrollback is preserved),
 * traps SIGWINCH to re-render, truncates to width-1 to avoid autowrap
 * flicker, honors NO_COLOR, and always restores the terminal on exit.
 */

import { argv, env, exit, stdout, stdin, stderr } from "node:process";
import { createInterface } from "node:readline";
import {
	type ConnectOptions,
	type Status,
	type VpnInfo,
	VpnManager,
	type UiAdapter,
	configNeedsAuth,
	defaultSearchDirs,
	findOvpnFiles,
	fmtElapsed,
	nameFromPath,
	tailLog,
} from "./vpn-core.js";

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

const NO_COLOR = !!env.NO_COLOR || !stdout.isTTY;
const C = NO_COLOR
	? {
			reset: "",
			bold: "",
			dim: "",
			red: "",
			green: "",
			yellow: "",
			blue: "",
			magenta: "",
			cyan: "",
			gray: "",
	  }
	: {
			reset: "\x1b[0m",
			bold: "\x1b[1m",
			dim: "\x1b[2m",
			red: "\x1b[31m",
			green: "\x1b[32m",
			yellow: "\x1b[33m",
			blue: "\x1b[34m",
			magenta: "\x1b[35m",
			cyan: "\x1b[36m",
			gray: "\x1b[90m",
	  };

function paint(s: string, ...codes: string[]): string {
	if (NO_COLOR) return s;
	return codes.join("") + s + C.reset;
}

// ---------------------------------------------------------------------------
// String width helpers (ASCII-friendly; good enough for filenames + logs)
// ---------------------------------------------------------------------------

/** Visible length ignoring ANSI escapes. */
function visLen(s: string): number {
	let n = 0;
	let inEsc = false;
	for (let i = 0; i < s.length; i++) {
		const ch = s[i];
		if (ch === "\x1b") {
			inEsc = true;
			continue;
		}
		if (inEsc) {
			if (ch === "m") inEsc = false;
			continue;
		}
		n++;
	}
	return n;
}

/** Truncate a string (may contain ANSI) to `width` visible columns. */
function truncateAnsi(s: string, width: number): string {
	if (visLen(s) <= width) return s;
	let n = 0;
	let out = "";
	let inEsc = false;
	for (let i = 0; i < s.length; i++) {
		const ch = s[i];
		if (ch === "\x1b") {
			inEsc = true;
			out += ch;
			continue;
		}
		if (inEsc) {
			out += ch;
			if (ch === "m") inEsc = false;
			continue;
		}
		if (n >= width) break;
		out += ch;
		n++;
	}
	if (!inEsc) out += C.reset;
	return out;
}

/** Right-pad a string to `width` visible columns (truncates if longer). */
function padField(s: string, width: number): string {
	const v = visLen(s);
	if (v > width) return truncateAnsi(s, width);
	return s + " ".repeat(width - v);
}

// ---------------------------------------------------------------------------
// Key parsing (raw mode)
// ---------------------------------------------------------------------------

interface KeyEvent {
	type: "char" | "enter" | "backspace" | "esc" | "ctrl-c" | "up" | "down" | "left" | "right" | "tab" | "unknown";
	ch?: string;
}

function parseKeys(buf: Buffer): KeyEvent[] {
	const out: KeyEvent[] = [];
	let i = 0;
	while (i < buf.length) {
		const b = buf[i];
		// Ctrl-C
		if (b === 0x03) {
			out.push({ type: "ctrl-c" });
			i++;
			continue;
		}
		// Enter
		if (b === 0x0d || b === 0x0a) {
			out.push({ type: "enter" });
			i++;
			continue;
		}
		// Backspace / Del
		if (b === 0x7f || b === 0x08) {
			out.push({ type: "backspace" });
			i++;
			continue;
		}
		// Tab
		if (b === 0x09) {
			out.push({ type: "tab" });
			i++;
			continue;
		}
		// Escape sequences
		if (b === 0x1b) {
			if (i + 2 < buf.length && buf[i + 1] === 0x5b) {
				const c = buf[i + 2];
				if (c === 0x41) {
					out.push({ type: "up" });
					i += 3;
					continue;
				}
				if (c === 0x42) {
					out.push({ type: "down" });
					i += 3;
					continue;
				}
				if (c === 0x43) {
					out.push({ type: "right" });
					i += 3;
					continue;
				}
				if (c === 0x44) {
					out.push({ type: "left" });
					i += 3;
					continue;
				}
			}
			// Bare Esc (or unrecognised sequence) — treat as Esc
			out.push({ type: "esc" });
			i++;
			continue;
		}
		// Printable (ignore other control bytes)
		if (b >= 0x20) {
			// UTF-8: grab the full codepoint run.
			let len = 1;
			if (b >= 0xc0) {
				if (b >= 0xf0) len = 4;
				else if (b >= 0xe0) len = 3;
				else len = 2;
			}
			const ch = buf.subarray(i, i + len).toString("utf8");
			out.push({ type: "char", ch });
			i += len;
			continue;
		}
		i++;
	}
	return out;
}

// ---------------------------------------------------------------------------
// Terminal control
// ---------------------------------------------------------------------------

const ALT_ENTER = "\x1b[?1049h";
const ALT_LEAVE = "\x1b[?1049l";
const HIDE_CURSOR = "\x1b[?25l";
const SHOW_CURSOR = "\x1b[?25h";
const CLEAR = "\x1b[2J";
const HOME = "\x1b[H";

function size(): { w: number; h: number } {
	return {
		w: Math.max(40, stdout.columns || 80),
		h: Math.max(12, stdout.rows || 24),
	};
}

// ---------------------------------------------------------------------------
// Status badge
// ---------------------------------------------------------------------------

function statusBadge(s: Status): string {
	switch (s) {
		case "connected":
			return paint("● connected", C.green, C.bold);
		case "connecting":
			return paint("◌ connecting", C.yellow);
		case "error":
			return paint("✖ error", C.red, C.bold);
		default:
			return paint("○ disconnected", C.gray);
	}
}

// ---------------------------------------------------------------------------
// Frame builder (responsive)
// ---------------------------------------------------------------------------

interface FrameInput {
	info: VpnInfo;
	configs: string[];
	selected: number;
	logLines: string[];
	mode: Mode;
	prompt?: { label: string; secret: boolean; value: string };
	message?: string;
	clock: string;
}

type Mode = "browse" | "prompt";

// --- border / row helpers (single box, proper tee junctions) ---
const DIM = () => C.dim;
const bar = (n: number) => paint("─".repeat(Math.max(0, n)), C.dim);

function titleBorder(w: number, title: string): string {
	const fill = w - 2 - visLen(title);
	return paint("┌", C.dim) + title + bar(fill) + paint("┐", C.dim);
}
function fullSep(w: number): string {
	return paint("├", C.dim) + bar(w - 2) + paint("┤", C.dim);
}
function bottomBorder(w: number): string {
	return paint("└", C.dim) + bar(w - 2) + paint("┘", C.dim);
}
function wideSep(w: number, listW: number, tee: string): string {
	const logW = w - 2 - 1 - listW;
	return paint("├", C.dim) + bar(listW) + paint(tee, C.dim) + bar(logW) + paint("┤", C.dim);
}
function row(content: string, w: number): string {
	return paint("│", C.dim) + padField(content, w - 2) + paint("│", C.dim);
}
function wideRow(left: string, right: string, listW: number, w: number): string {
	const logW = w - 2 - 1 - listW;
	return paint("│", C.dim) + padField(left, listW) + paint("│", C.dim) + padField(right, logW) + paint("│", C.dim);
}

// --- content-only pane bodies (no borders) ---
function listBody(inp: FrameInput, rows: number, innerW: number): string[] {
	const out: string[] = [];
	const items = inp.configs;
	const start = Math.max(0, Math.min(inp.selected - Math.floor(rows / 2), Math.max(0, items.length - rows)));
	for (let r = 0; r < rows; r++) {
		const idx = start + r;
		if (idx >= items.length) {
			out.push("");
			continue;
		}
		const cfg = items[idx];
		const up = inp.info.configPath === cfg && (inp.info.status === "connected" || inp.info.status === "connecting");
		const cursor = idx === inp.selected ? paint("▸", C.cyan, C.bold) : paint(" ", C.dim);
		const dot = up ? paint("●", C.green) : paint("○", C.dim);
		const nm = nameFromPath(cfg);
		const name = idx === inp.selected ? paint(nm, C.bold) : paint(nm, C.dim);
		out.push(` ${cursor} ${dot} ${name}`);
	}
	return out;
}
function logBody(inp: FrameInput, rows: number, innerW: number): string[] {
	const log = inp.logLines.slice(-rows);
	const out: string[] = [];
	for (let r = 0; r < rows; r++) {
		const line = log[r] ?? "";
		out.push(line ? " " + paint(dimLog(line), C.dim) : "");
	}
	return out;
}

function buildFrame(inp: FrameInput): string[] {
	const { w, h } = size();
	const lines: string[] = [];

	// ── status line ──
	const status = inp.info.status;
	const lock = status === "connected" ? paint("🔒", C.green) : status === "connecting" ? paint("🔒", C.yellow) : paint("🔒", C.gray);
	const name = inp.info.name ? paint(inp.info.name, C.bold) : paint("(no tunnel)", C.dim);
	const badge = statusBadge(status);
	const parts = [lock, name, badge];
	if (inp.info.ip) parts.push(paint(inp.info.ip, C.cyan, C.bold));
	if (inp.info.dev) parts.push(paint(inp.info.dev, C.dim));
	if (status === "connected" && inp.info.startTime) parts.push(paint(fmtElapsed(Date.now() - inp.info.startTime), C.magenta));
	else if (status === "connecting" && inp.info.connectTime) parts.push(paint(`${Math.floor((Date.now() - inp.info.connectTime) / 1000)}s`, C.dim));
	if (inp.info.pid) parts.push(paint(`pid ${inp.info.pid}`, C.dim));
	const statusStr = parts.join(paint("  ", C.dim));

	const titleStr = paint(" pi-vpn ", C.bold, C.cyan) + paint(inp.clock, C.dim);

	// header: top border + status
	lines.push(titleBorder(w, titleStr));
	lines.push(row(statusStr, w));

	const wide = w >= 100;
	const innerW = w - 2;

	if (wide) {
		// fixed rows: top(1)+status(1)+sepTop(1)+titles(1)+sepBot(1)+keybinds(1)+bottom(1) = 7
		const contentRows = Math.max(1, h - 7);
		const listW = Math.min(42, Math.floor(w * 0.38));
		lines.push(wideSep(w, listW, "┬"));
		lines.push(wideRow(paint(" Configs", C.bold), paint(" Log", C.bold), listW, w));
		const lb = listBody(inp, contentRows, listW);
		const lg = logBody(inp, contentRows, innerW - 1 - listW);
		for (let r = 0; r < contentRows; r++) lines.push(wideRow(lb[r] ?? "", lg[r] ?? "", listW, w));
		lines.push(wideSep(w, listW, "┴"));
	} else {
		// fixed rows: top+status+sep+cfgTitle+sep+logTitle+sep+keybinds+bottom = 9
		const contentRows = Math.max(1, h - 9);
		const listRows = Math.max(1, Math.floor(contentRows * 0.42));
		const logRows = Math.max(1, contentRows - listRows);
		lines.push(fullSep(w));
		lines.push(row(paint(" Configs", C.bold), w));
		const lb = listBody(inp, listRows, innerW);
		for (let r = 0; r < listRows; r++) lines.push(row(lb[r] ?? "", w));
		lines.push(fullSep(w));
		lines.push(row(paint(" Log", C.bold), w));
		const lg = logBody(inp, logRows, innerW);
		for (let r = 0; r < logRows; r++) lines.push(row(lg[r] ?? "", w));
		lines.push(fullSep(w));
	}

	// footer — the body's bottom separator already sits directly above this.
	let kb: string;
	if (inp.mode === "prompt" && inp.prompt) {
		const val = inp.prompt.secret ? "•".repeat(inp.prompt.value.length) : inp.prompt.value;
		kb = " " + paint(inp.prompt.label + ": ", C.cyan) + val + paint("▌", C.dim);
	} else {
		kb = [
			paint("↑↓/jk", C.bold) + paint(" select", C.dim),
			paint("⏎", C.bold) + paint(" connect", C.dim),
			paint("d", C.bold) + paint(" disconnect", C.dim),
			paint("r", C.bold) + paint(" refresh", C.dim),
			paint("q", C.bold) + paint(" quit", C.dim),
		].join(paint("   ", C.dim));
	}
	const foot = kb + (inp.message ? "   " + paint(inp.message, C.yellow) : "");
	lines.push(row(foot, w));
	lines.push(bottomBorder(w));

	return lines;
}

/** Dim timestamps in log lines, keep the rest readable. */
function dimLog(line: string): string {
	// Typical openvpn: "Wed Jul 16 12:00:00 2025 ..." — dim the leading timestamp.
	const m = line.match(/^(\w{3} \w{3} +\d+ [\d:]+ \d+)(.*)$/);
	if (m) return paint(m[1], C.gray) + m[2];
	return line;
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

interface PromptState {
	label: string;
	secret: boolean;
	value: string;
	resolve: (v: string | undefined) => void;
}

class App implements UiAdapter {
	private manager = new VpnManager();
	private configs: string[] = [];
	private selected = 0;
	private mode: Mode = "browse";
	private promptState: PromptState | null = null;
	private message = "";
	private messageTimer: ReturnType<typeof setTimeout> | null = null;
	private renderTimer: ReturnType<typeof setInterval> | null = null;
	private logFile: string | null = null;
	private stopped = false;

	constructor() {
		this.manager.reattach();
	}

	// ---- UiAdapter (used by VpnManager for sudo / vpn creds) ----
	async prompt(label: string, opts?: { secret?: boolean }): Promise<string | undefined> {
		return new Promise<string | undefined>((resolve) => {
			this.promptState = { label, secret: !!opts?.secret, value: "", resolve };
			this.mode = "prompt";
			this.render();
		});
	}

	// ---- lifecycle ----
	async run(initial?: string): Promise<void> {
		this.rescan();
		if (initial) {
			const idx = this.configs.indexOf(initial);
			if (idx >= 0) this.selected = idx;
		}
		this.enterScreen();
		this.render(); // paint immediately — don't wait for the first 1s tick
		this.renderTimer = setInterval(() => {
			this.manager.refreshIp();
			this.render();
		}, 1000);
		stdin.on("data", (buf: Buffer) => this.handleData(buf));
		// re-render immediately on terminal / tmux-pane resize
		stdout.on("resize", () => this.render());
		// keep the process alive until stopped
		await new Promise<void>((resolve) => {
			this.onQuit = resolve;
		});
	}

	private onQuit: (() => void) | null = null;

	private rescan(): void {
		this.configs = findOvpnFiles(defaultSearchDirs(process.cwd()));
		if (this.selected >= this.configs.length) this.selected = Math.max(0, this.configs.length - 1);
		this.logFile = this.manager.currentLogFile();
	}

	private flash(msg: string): void {
		this.message = msg;
		if (this.messageTimer) clearTimeout(this.messageTimer);
		this.messageTimer = setTimeout(() => {
			this.message = "";
			this.render();
		}, 4000);
	}

	// ---- input ----
	private handleData(buf: Buffer): void {
		const events = parseKeys(buf);
		for (const ev of events) {
			if (this.mode === "prompt") {
				this.handlePromptKey(ev);
			} else {
				this.handleBrowseKey(ev);
			}
		}
		this.render();
	}

	private handlePromptKey(ev: KeyEvent): void {
		const p = this.promptState;
		if (!p) return;
		switch (ev.type) {
			case "enter":
				this.mode = "browse";
				this.promptState = null;
				p.resolve(p.value);
				break;
			case "backspace":
				p.value = p.value.slice(0, -1);
				break;
			case "esc":
			case "ctrl-c":
				this.mode = "browse";
				this.promptState = null;
				p.resolve(undefined);
				break;
			case "char":
				if (ev.ch) p.value += ev.ch;
				break;
			default:
				break;
		}
	}

	private handleBrowseKey(ev: KeyEvent): void {
		switch (ev.type) {
			case "up":
			case "char":
				if (ev.type === "char" && ev.ch !== "k") break;
				this.selected = Math.max(0, this.selected - 1);
				return;
			case "down":
				this.selected = Math.min(Math.max(0, this.configs.length - 1), this.selected + 1);
				return;
		}
		if (ev.type === "char") {
			switch (ev.ch) {
				case "j":
					this.selected = Math.min(Math.max(0, this.configs.length - 1), this.selected + 1);
					return;
				case "q":
					this.quit();
					return;
				case "r":
					this.rescan();
					this.manager.refreshIp();
					this.flash("refreshed");
					return;
				case "d":
					void this.doDisconnect();
					return;
			}
		}
		if (ev.type === "enter") {
			void this.doConnectSelected();
			return;
		}
		if (ev.type === "ctrl-c" || ev.type === "esc") {
			this.quit();
		}
	}

	private async doConnectSelected(): Promise<void> {
		const cfg = this.configs[this.selected];
		if (!cfg) {
			this.flash("no config selected");
			return;
		}
		const name = nameFromPath(cfg);
		try {
			this.flash(`connecting to ${name}…`);
			await this.manager.connect(this, { configPath: cfg }, process.cwd());
			this.logFile = this.manager.currentLogFile();
			this.flash(`connected to ${name}`);
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			this.flash(`failed: ${msg}`);
		}
	}

	private async doDisconnect(): Promise<void> {
		const name = this.manager.state.name;
		try {
			await this.manager.disconnect();
			this.flash(`disconnected${name ? " from " + name : ""}`);
		} catch (e) {
			this.flash(`disconnect failed: ${e instanceof Error ? e.message : String(e)}`);
		}
	}

	// ---- render ----
	private render(): void {
		if (this.stopped) return;
		const info = this.manager.snapshot();
		const logLines = this.logFile ? tailLog(this.logFile, 200) : [];
		const clock = new Date().toLocaleTimeString();
		const frame = buildFrame({
			info,
			configs: this.configs,
			selected: this.selected,
			logLines,
			mode: this.mode,
			prompt: this.promptState ?? undefined,
			message: this.message,
			clock,
		});
		this.paint(frame);
	}

	private paint(lines: string[]): void {
		// Clamp to the real terminal height so a miscalculation can never overflow.
		const maxRows = stdout.rows || 24;
		const view = lines.length > maxRows ? lines.slice(0, maxRows) : lines;
		// HOME (no newline after it), then each line + clear-to-EOL, separated by
		// CRLF, with NO trailing newline — otherwise the cursor advances past the
		// last row and the terminal scrolls the top off-screen.
		// (Raw mode disables OPOST, so \n alone won't carriage-return; use \r\n.)
		let buf = HOME;
		for (let i = 0; i < view.length; i++) {
			buf += view[i] + "\x1b[K";
			if (i < view.length - 1) buf += "\r\n";
		}
		stdout.write(buf);
	}

	private enterScreen(): void {
		stdout.write(ALT_ENTER + HIDE_CURSOR);
	}

	private leaveScreen(): void {
		stdout.write(SHOW_CURSOR + ALT_LEAVE);
	}

	private quit(): void {
		if (this.stopped) return;
		this.stopped = true;
		if (this.renderTimer) clearInterval(this.renderTimer);
		this.leaveScreen();
		// NOTE: the tunnel is a detached daemon and intentionally survives.
		this.onQuit?.();
	}
}

// ---------------------------------------------------------------------------
// Terminal raw-mode setup / teardown
// ---------------------------------------------------------------------------

function withRawTerminal<T>(fn: () => Promise<T>): Promise<T> {
	const prevRaw = stdin.isTTY ? stdin.isRaw : undefined;
	const prevMouse = undefined;
	const restore = () => {
		try {
			if (stdin.isTTY) stdin.setRawMode(prevRaw ?? false);
			stdin.pause();
		} catch {
			/* ignore */
		}
	};
	// graceful exits
	const handlers = ["SIGINT", "SIGTERM", "SIGHUP"] as const;
	const onSignal = () => {
		restore();
		exit(0);
	};
	for (const sig of handlers) process.on(sig, onSignal);
	process.on("exit", restore);

	if (stdin.isTTY) stdin.setRawMode(true);
	stdin.resume();

	return fn().finally(() => {
		restore();
		for (const sig of handlers) process.off(sig, onSignal);
	});
}

// ---------------------------------------------------------------------------
// Non-interactive CLI subcommands
// ---------------------------------------------------------------------------

function outLine(s: string): void {
	stdout.write(s + "\n");
}

async function cliStatus(): Promise<void> {
	const m = new VpnManager();
	m.reattach();
	m.refreshIp();
	const i = m.snapshot();
	if (i.status === "disconnected") {
		outLine("disconnected");
	} else {
		outLine(
			[
				i.status,
				i.name,
				i.ip ?? "-",
				i.dev ?? "-",
				i.startTime ? fmtElapsed(Date.now() - i.startTime) : "-",
				i.configPath ?? "",
			]
				.filter(Boolean)
				.join("  "),
		);
	}
	exit(i.status === "connected" ? 0 : 1);
}

async function cliDisconnect(): Promise<void> {
	const m = new VpnManager();
	m.reattach();
	await m.disconnect();
	outLine("disconnected");
	exit(0);
}

async function cliList(): Promise<void> {
	const files = findOvpnFiles(defaultSearchDirs(process.cwd()));
	if (files.length === 0) {
		stderr.write("No .ovpn/.opvn files found.\n");
		exit(1);
	}
	for (const f of files) outLine(f);
	exit(0);
}

/** Minimal UiAdapter for non-interactive mode: prompts via readline. */
function readlineUi(): UiAdapter {
	const rl = createInterface({ input: stdin, output: stdout, terminal: true });
	return {
		async prompt(label, opts) {
			return new Promise((resolve) => {
				const q = label + (opts?.secret ? " (input hidden): " : ": ");
				if (opts?.secret) {
					// Mask input.
					const stdinAny = stdin as NodeJS.ReadStream & { on: typeof stdin.on };
					const onData = (ch: Buffer) => {
						const c = ch.toString();
						if (c === "\r" || c === "\n") {
							stdinAny.off("data", onData);
							stdout.write("\n");
						} else if (c === "\u0003") {
							stdout.write("\n");
							process.exit(130);
						} else if (c === "\u007f" || c === "\b") {
							// backspace handling is best-effort here
						} else {
							stdout.write("*");
						}
					};
					stdinAny.on("data", onData);
				}
				rl.question(q, (ans) => resolve(ans));
			});
		},
	};
}

async function cliConnect(opts: ConnectOptions): Promise<void> {
	const m = new VpnManager();
	m.reattach();
	try {
		const info = await m.connect(readlineUi(), opts, process.cwd());
		outLine(`connected to ${info.name} (${info.ip ?? "no ip"})`);
		exit(0);
	} catch (e) {
		stderr.write(`connect failed: ${e instanceof Error ? e.message : String(e)}\n`);
		exit(1);
	}
}

// ---------------------------------------------------------------------------
// Argument parsing + entry
// ---------------------------------------------------------------------------

function usage(code = 1): never {
	stderr.write(
		[
			"pi-vpn — terminal OpenVPN manager",
			"",
			"Usage:",
			"  pi-vpn                       launch the TUI",
			"  pi-vpn <file.ovpn>           launch the TUI with a preselected config",
			"  pi-vpn connect <file>        connect non-interactively, then exit",
			"  pi-vpn disconnect            tear down the current tunnel, then exit",
			"  pi-vpn status                one-line status, then exit",
			"  pi-vpn list                  list discovered .ovpn files",
			"",
			"Connect options:",
			"  --username <user>            VPN username (for auth-user-pass profiles)",
			"  --password <pass>            VPN password (prefer --auth-file or a prompt)",
			"  --auth-file <path>           path to an existing auth-user-pass file",
			"",
			"Environment:",
			"  PI_VPN_SUDO_PASS             sudo password (for non-interactive use)",
			"  NO_COLOR                     disable color output",
			"",
		].join("\n"),
	);
	exit(code);
}

async function main(): Promise<void> {
	const args = argv.slice(2);

	if (args.length === 0 || args[0] === "tui") {
		if (!stdout.isTTY) {
			stderr.write("pi-vpn: TUI requires an interactive terminal.\n");
			exit(1);
		}
		await withRawTerminal(async () => {
			const app = new App();
			await app.run();
		});
		return;
	}

	const sub = args[0];

	if (sub === "-h" || sub === "--help" || sub === "help") usage(0);

	if (sub === "status") return cliStatus();
	if (sub === "disconnect" || sub === "stop" || sub === "down") return cliDisconnect();
	if (sub === "list") return cliList();

	if (sub === "connect") {
		const rest = args.slice(1);
		const opts: ConnectOptions = { configPath: "" };
		for (let i = 0; i < rest.length; i++) {
			const a = rest[i];
			if (a === "--username") opts.username = rest[++i];
			else if (a === "--password") opts.password = rest[++i];
			else if (a === "--auth-file") opts.authFile = rest[++i];
			else if (!opts.configPath) opts.configPath = a;
		}
		if (!opts.configPath) usage();
		return cliConnect(opts);
	}

	// Bare .ovpn path → launch TUI preselected (but only if it's an .ovpn file).
	if (sub.toLowerCase().endsWith(".ovpn") || sub.toLowerCase().endsWith(".opvn")) {
		if (!stdout.isTTY) {
			stderr.write("pi-vpn: TUI requires an interactive terminal.\n");
			exit(1);
		}
		await withRawTerminal(async () => {
			const app = new App();
			await app.run(sub);
		});
		return;
	}

	usage();
}

main().catch((e) => {
	stderr.write(`pi-vpn: ${e instanceof Error ? e.message : String(e)}\n`);
	exit(1);
});
