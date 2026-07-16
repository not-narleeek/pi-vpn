# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2025-07-16

### Added — standalone TUI
- `tui/vpn-core.ts` — framework-agnostic OpenVPN core (manager, privilege model,
  credential handling, `.ovpn` discovery, log monitoring, reattach) with **no
  runtime npm dependencies**. Shared conceptually with the pi extension.
- `tui/vpn-tui.ts` — a keyboard-driven, **tmux-friendly** terminal UI:
  responsive single-box layout (side-by-side at ≥100 cols, stacked below),
  live status bar + rolling log, alternate-screen buffer, immediate re-render
  on `SIGWINCH`/pane resize, honors `NO_COLOR`, and clean teardown on
  `q`/`Esc`/`Ctrl-C`/`SIGTERM`.
- CLI entry points: `pi-vpn` (TUI), `pi-vpn connect <file>`, `pi-vpn
  disconnect`, `pi-vpn status`, `pi-vpn list`, with `--username`/`--password`/
  `--auth-file` flags and masked credential prompts.
- Bundled to a single zero-dependency `dist/pi-vpn.cjs` via esbuild (dev-only);
  `npm run build` / auto-built on install via the `prepare` script.
- `docs/TUI.md` — dedicated TUI documentation.

### Fixed (pi extension)
- `vpn_connect` tool passed `path` where `connectVPN` expects `configPath`, so
  the **tool** path was broken at runtime (only the `/vpn connect` command
  worked). Now remaps the parameter correctly. Found via `tsc` type-check.
- `killPid(result.pid)` could receive `null`; now guarded.

### Changed
- Added `@types/node` and `esbuild` dev dependencies (build-time only).
- `package.json`: `bin` entry for `pi-vpn`, `build`/`prepare` scripts,
  `tsconfig.tui.json` for TUI type-checking. `npm run check` now type-checks
  both the extension and the TUI.

## [0.1.0] - 2025-07-16

### Added
- Initial release as a standalone, distributable pi package.
- `extensions/vpn.ts` — pi extension exposing four tools
  (`vpn_connect`, `vpn_disconnect`, `vpn_status`, `vpn_list`), a `/vpn`
  command (connect / disconnect / status / list), and an interactive TUI
  status panel with a live footer.
- Daemon-based tunnels: connections start with `openvpn --daemon` so they
  **survive pi quitting** — essential for long CTF / lab sessions. The
  extension reattaches to a running tunnel on session start via a persisted
  `state.json` + PID liveness check.
- Privilege model: uses root directly if pi runs as root, else passwordless
  `sudo -n`, else `$PI_VPN_SUDO_PASS`, else an in-session prompt (cached in
  memory only, never written to disk).
- Credential handling: detects `auth-user-pass` profiles, prompts
  interactively or accepts `username`/`password`/`authFile` args, writes
  temp auth files with `0600` perms, and deletes them immediately after use.
- Log monitoring: watches the openvpn log for `Initialization Sequence
  Completed` or failure patterns (`AUTH_FAILED`, fatal errors, tun-device
  errors, timeouts) and reports a clear reason on failure.
- Auto-discovery of `.ovpn`/`.opvn` configs in the cwd, `~/ctf`,
  `~/Downloads`, `~/hackerone`, `~/security`, and `~`.
- Live footer showing connection name · status · VPN IP · elapsed time.
- Config via `PI_VPN_SUDO_PASS`.
- `package.json` pi manifest (`pi.extensions`), `tsconfig.json` for local
  type-checking, MIT license, README, and architecture docs.

[Unreleased]: https://github.com/not-narleeek/pi-vpn/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/not-narleeek/pi-vpn/releases/tag/v0.1.0
