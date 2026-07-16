# Architecture

A deeper dive into how `pi-vpn` brings up, monitors, and tears down OpenVPN
tunnels, and how it keeps state across pi restarts. For usage, see the
[README](../README.md).

## Design goals

- **One command to connect.** Point it at an `.ovpn` and you're on the VPN.
- **Survive pi quitting.** Long CTF / lab sessions outlast any single agent
  run. The tunnel is a detached daemon, not a child of pi.
- **Survive pi restarting.** On a new session, reattach to a tunnel that's
  still up from before.
- **No credential leakage.** Passwords are held in memory only, written to
  `0600` temp files only for the duration of the connect, and deleted
  immediately — never logged, never persisted.
- **Clear failure messages.** Parse the openvpn log so a bad cert, auth
  failure, or missing tun device reads as a human sentence, not a wall of log.
- **Thin & dependency-free.** Pure TypeScript + Node stdlib + the system
  `openvpn` binary. No Python, no daemons of our own.

## The layers

```
┌──────────────────────────────────────────────────────────────────────┐
│                              pi (the agent)                           │
│   ┌────────────────────────────────────────────────────────────────┐ │
│   │  extensions/vpn.ts   ←── this package (TypeScript)              │ │
│   │   • 4 tools: vpn_connect · vpn_disconnect · vpn_status · …     │ │
│   │   • /vpn command + interactive TUI status panel                │ │
│   │   • live footer (name · status · IP · elapsed)                 │ │
│   │   • privilege mgmt · credential handling · log monitoring      │ │
│   └───────────────────┬────────────────────────────────────────────┘ │
└───────────────────────┼────────────────────────────────────────────────┘
                        │  spawnSync("sudo", ["-n","openvpn", …])  or
                        │  spawnSync("openvpn", […])  (if root)
┌───────────────────────▼────────────────────────────────────────────────┐
│                   openvpn --daemon (detached)                          │
│   writes pid file + log file · opens tun/tap · establishes tunnel       │
│   SURVIVES pi exiting (it is not a child of pi)                         │
└────────────────────────────────────────┬───────────────────────────────┘
                                         │  ip -4 addr (read-only inspection)
                       ┌─────────────────▼─────────────────┐
                       │   the VPN tunnel (tun0/tap0…)      │
                       └────────────────────────────────────┘
```

Unlike `pi-ghidra` / `pi-caido`, there is **no helper script** — the extension
is pure TypeScript that shells out to the system `openvpn` binary and reads
`ip`/`/proc`-style data back. That keeps the package a single auditable file.

### File layout

```
pi-vpn/
├── extensions/
│   └── vpn.ts          # the whole extension: tools, command, panel, footer
├── docs/
│   └── ARCHITECTURE.md # this file
├── package.json        # pi manifest (pi.extensions) + npm metadata
├── tsconfig.json       # local type-checking only (pi compiles the extension)
├── README.md
├── CHANGELOG.md
└── LICENSE
```

## State on disk

```
~/.pi/vpn/
├── state.json          # persisted ONLY while connected: name, configPath,
│                       #   pid, startTime, dev  (mode 0600; deleted on disconnect)
├── logs/<slug>.log     # openvpn log for the current/last connection
├── pid/<slug>.pid      # openvpn pid file
└── auth-<rand>.txt     # TEMP auth-user-pass file (0600), deleted after connect
```

`<slug>` is derived from the connection name (filename) — sanitized to
`[a-z0-9_-]`, max 40 chars.

> Auth files are created with mode `0600`, used only for the duration of the
> `connect` call, and unlinked in a `finally` block — so they are removed even
> if the connect fails or is cancelled.

## Execution flow

### 1. Connect (`vpn_connect` / `/vpn connect`)

1. **Resolve** the config path (relative to `ctx.cwd`). Bail if missing.
2. **Tear down first** if a tunnel is already up/connecting (so a new connect
   implicitly switches servers).
3. **Credentials** — in priority order:
   - explicit `authFile` arg → use it as-is.
   - explicit `username`/`password` args → write a temp `0600` auth file.
   - profile has a bare `auth-user-pass` (detected by scanning the config) and
     no creds given → prompt interactively in the UI, or error in headless.
4. **Privileges** — `ensureSudo()` (see below).
5. **Launch** as a daemon:
   ```
   sudo -n openvpn --config <cfg> --daemon ovpn-pi-<slug> \
       --writepid <pid>/<slug>.pid --log <logs>/<slug>.log \
       [--auth-user-pass <auth>]
   ```
   `--daemon` detaches it from pi's process tree — this is the key to survival.
6. **Monitor** the log (see below) until success / failure / timeout.
7. On success: read the tunnel interface via `ip -j -4 addr show`, record
   `{status:"connected", ip, dev, pid, startTime}`, persist `state.json`,
   notify, and start the 1 s footer-refresh timer.

### 2. Privilege model (`ensureSudo`)

`openvpn` needs root to create the tun device. The extension never asks for
root it doesn't need — it tries, in order, and stops at the first that works:

| # | Method | Notes |
|---|--------|-------|
| 1 | pi already runs as root | `spawnSync("openvpn", …)` directly |
| 2 | passwordless `sudo -n -v` | common on dedicated pentest boxes |
| 3 | `$PI_VPN_SUDO_PASS` | for automation / CI; fed via `sudo -S` |
| 4 | in-session UI prompt | cached **in memory only** for this process |

The cached password lives in a module-scoped variable and is **never** written
to disk. `sudo -v` is re-checked before each privileged call to refresh the
sudo timestamp.

### 3. Log monitoring (`monitorLog`)

Polls the log file every 500 ms for up to 60 s, reading only the **new bytes**
since the last poll (handles rotation/truncation):

- **Success:** regex `Initialization Sequence Completed` → also capture the
  `TUN/TAP device <dev> opened` line to learn the interface name.
- **Failure** (first match wins):
  - `AUTH_FAILED` → "authentication failed (check VPN credentials)"
  - `private key password verification failed` → key password rejected
  - `Options error:` → config error (first line extracted)
  - `Exiting due to fatal error` → the 3 lines around it
  - `Cannot ioctl TUNSETIFF` → tun-device conflict / no privileges
  - `Inactivity timeout`
- **Process death:** if the pid is no longer alive (`kill -0`, where `EPERM`
  counts as "exists" for root-owned pids) before success → fail with the
  matched reason or the tail of the log.

### 4. The live footer + status panel

- A 1 s `setInterval` repaints the footer: 🔒 `name · ● · 10.10.0.5 · 12:03`.
- `/vpn` (no args) in TUI mode opens an interactive panel rendered via
  `ctx.ui.custom(...)`: a themed status box with keyboard hints
  (`d` disconnect · `l` list/connect · `r` refresh · `q` close). The panel
  caches its rendered lines per terminal width for cheap repaints.
- On `session_start` the timer (re)starts only if a tunnel is actually up.

### 5. Disconnect (`vpn_disconnect` / `/vpn disconnect`)

1. Stop the footer timer.
2. Read the pid (from state, or from the pid file as a fallback).
3. `kill -TERM` it (via root, or `sudo -n kill`).
4. Reset state to blank, `rm` `state.json`, repaint the idle footer.

### 6. Reattach on restart (`reattach`)

On `session_start`, before painting anything:

1. Read `state.json`. If absent → idle, done.
2. If the recorded pid is **not** alive (plain `kill -0`, `EPERM` = alive) →
   the tunnel died while pi was away; clear state, delete `state.json`, idle.
3. If alive → query the tunnel interface for the current IP, restore the full
   `connected` state (including `startTime` so the elapsed counter continues),
   and start the footer timer.

This is what makes the tunnel feel persistent across agent restarts.

## Tunnel interface detection (`getTunnelIface`)

Read-only (no root needed). Prefers machine-readable output:

1. `ip -j -4 addr show` → parse JSON, find the first `tun|tap|ppp|ovpn*`
   interface with an IPv4 `addr_info.local`.
2. Fallback: text-parse `ip -4 addr show` line by line.

Optionally filtered to a specific `dev` (the one openvpn reported).

## Security notes

- **The tunnel outlives pi by design.** This is a feature, not a leak — but it
  means a forgotten tunnel stays up until you `/vpn disconnect` or kill the
  pid. The footer + `state.json` make it visible.
- **Passwords are ephemeral.** Held in a process-scoped variable; the only
  disk artifact is a `0600` auth file that exists solely during the `connect`
  call and is removed in `finally`.
- **`state.json` carries no secrets** — only `name`, `configPath`, `pid`,
  `startTime`, `dev`. It is written with mode `0600` and deleted on
  disconnect.
- **Runs with your privileges.** Like all pi packages, this executes code
  (`openvpn`, `sudo`, `ip`, `kill`). There is exactly one source file to audit:
  `extensions/vpn.ts`.
