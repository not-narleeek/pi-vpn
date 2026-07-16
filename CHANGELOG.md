# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
