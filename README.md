# pi-vpn

> **Drive [OpenVPN](https://openvpn.net/) from [pi](https://pi.dev).** Bring up CTF & lab VPN tunnels from an `.ovpn` with a single command, watch a live status line tick by, and — crucially — let the tunnel keep running even after pi quits. Built for security researchers who spin up Hack The Box / TryHackMe / engagement VPNs every day.

`pi-vpn` is a [pi package](https://pi.dev/packages) that exposes OpenVPN as four first-class agent tools plus a `/vpn` command, an interactive TUI status panel, and a live footer. It handles privileges, credentials, and log parsing for you, and runs the tunnel as a **detached daemon** so a long pentest session never dies when your agent restarts. One TypeScript extension, no dependencies, no helper scripts.

---

## Table of contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Install](#install)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## What it does

Point the agent at an `.ovpn` (or let it find one) and it can:

- **connect** to the OpenVPN server in one call, prompting for credentials only if the profile needs them,
- show a **live status footer** — name · status · VPN IP · elapsed time — that updates every second,
- **monitor the connection** for success or a human-readable failure (bad cert, auth failed, tun-device conflict, timeout),
- **list** `.ovpn`/`.opvn` files in your workspace and common directories,
- **disconnect**, and
- **reattach** to a tunnel that's still up from a previous session.

The package gives the agent these tools:

| Tool | What the agent uses it for |
|------|----------------------------|
| `vpn_connect` | Connect to (or switch) an OpenVPN tunnel from an `.ovpn` file. Pass username/password only if the user gave them; otherwise let the extension prompt. |
| `vpn_disconnect` | Tear down the current tunnel. |
| `vpn_status` | Report current status: name, status, VPN IP, device, PID, elapsed. |
| `vpn_list` | Discover `.ovpn`/`.opvn` files in the workspace and common dirs. |

And a `/vpn` command for you:

```
/vpn                       interactive status panel (TUI)
/vpn connect <file.ovpn>   connect (prompts for creds if the profile needs them)
/vpn <file.ovpn>           shorthand for connect
/vpn disconnect            tear the current tunnel down
/vpn status                one-line status notification
/vpn list                  pick an .ovpn and connect
```

A live footer (🔒 `htb · ● · 10.10.0.5 · 12:03`) shows readiness at a glance.

---

## Requirements

| Component | Version | Notes |
|-----------|---------|-------|
| **pi** | any recent | the agent that loads this package — `npm i -g @earendil-works/pi-coding-agent` |
| **OpenVPN** | 2.5+ | the `openvpn` binary on `PATH`. On Kali/Debian: `apt install openvpn`. |
| **`sudo` / root** | — | `openvpn` needs root to create the tun device. See [Privilege model](#how-it-works). |
| **`ip` (iproute2)** | — | used for read-only tunnel-IP detection; present on virtually all Linux. |
| **Node** | 18+ | for the TypeScript extension |

> Linux-only. OpenVPN's tun-device model is Linux-centric; this package has not
> been tested on macOS/Windows.

---

## Install

Pick **one** of the three sources. `pi install` writes to user settings
(`~/.pi/agent/settings.json`) by default; add `-l` for project-local settings.

### 1. From git (recommended — always latest)

```bash
pi install git:github.com/not-narleeek/pi-vpn
```

Pin a tag/commit if you want reproducibility:

```bash
pi install git:github.com/not-narleeek/pi-vpn@v0.1.0
```

### 2. From npm (once published)

```bash
pi install npm:pi-vpn
```

### 3. From a local clone (for development)

```bash
git clone https://github.com/not-narleeek/pi-vpn
cd pi-vpn
npm install        # installs TypeScript peer deps for local type-checking
pi install .       # or: pi install ./pi-vpn  (absolute or relative path)
```

Verify it loaded:

```bash
pi list                 # pi-vpn should appear under packages
/vpn status             # inside a pi session
```

Try it without committing it to settings:

```bash
pi -e git:github.com/not-narleeek/pi-vpn     # ephemeral, current run only
```

> **Updating:** `pi update --extensions` reconciles git packages to their
> pinned ref; `pi update npm:pi-vpn` updates a single package.
> `pi remove npm:pi-vpn` (or the git: spec) uninstalls.

---

## Quick start

Inside a pi session, anywhere you have an `.ovpn`:

```text
> connect to the htb vpn using ~/Downloads/lab_norlek.ovpn

# The agent calls vpn_connect; if the profile needs a username/password and
# you didn't pass them, the extension prompts you. The footer lights up:
#   🔬 htb · ● · 10.10.14.23 · 0:04
```

Don't remember the filename? Let the agent find it:

```text
> list my vpn configs and connect to the tryhackme one

# Agent runs vpn_list (scans cwd, ~/ctf, ~/Downloads, ~/hackerone, ~/security, ~),
# then vpn_connect on your pick.
```

The tunnel keeps running even after pi exits:

```text
> disconnect from the vpn when you're done

# Agent calls vpn_disconnect. Until then, the daemonized openvpn survives
# pi quitting — reopen pi later and it reattaches automatically.
```

---

## Architecture

Two layers, no helper scripts. (Full deep-dive:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).)

```
┌──────────────────────────────────────────────────────────────────────┐
│                              pi (the agent)                           │
│   ┌────────────────────────────────────────────────────────────────┐ │
│   │  extensions/vpn.ts   ←── this package (TypeScript, stdlib only) │ │
│   │   • 4 tools + /vpn command + interactive status panel + footer  │ │
│   │   • privilege mgmt · credential handling · log monitoring       │ │
│   └───────────────────┬────────────────────────────────────────────┘ │
└───────────────────────┼────────────────────────────────────────────────┘
                        │  spawnSync("sudo", ["-n","openvpn", …])  (or openvpn if root)
┌───────────────────────▼────────────────────────────────────────────────┐
│                openvpn --daemon  (detached — not a child of pi)         │
│   writes pid + log · opens tun/tap · SURVIVES pi quitting               │
└────────────────────────────────────────────────────────────────────────┘
```

**Why no helper script?** Unlike `pi-ghidra`/`pi-caido`, there's nothing to
bridge — `openvpn` is a normal CLI. The extension just orchestrates: resolves
the config, sorts credentials, escalates privileges, launches the daemon, and
parses the log back. That makes the whole package a single auditable
TypeScript file.

### File layout

```
pi-vpn/
├── extensions/
│   └── vpn.ts          # the whole extension: tools, command, panel, footer
├── docs/
│   └── ARCHITECTURE.md # lifecycle, privilege model, log parsing, reattach
├── package.json        # pi manifest (pi.extensions) + npm metadata
├── tsconfig.json       # local type-checking only (pi compiles the extension)
├── README.md
├── CHANGELOG.md
└── LICENSE
```

---

## How it works

### 1. The daemon model

Connections start with:

```
sudo -n openvpn --config <cfg> --daemon ovpn-pi-<slug> \
    --writepid <pid>/<slug>.pid --log <logs>/<slug>.log \
    [--auth-user-pass <auth>]
```

`--daemon` detaches openvpn from pi's process tree. **This is intentional and
load-bearing**: a CTF / lab VPN must outlive any single agent run. You
disconnect explicitly with `/vpn disconnect` (or by killing the pid).

### 2. Privilege model

`openvpn` needs root for the tun device. The extension never asks for more
than necessary — it tries, in order, and stops at the first that works:

| # | Method | Notes |
|---|--------|-------|
| 1 | pi already runs as root | `openvpn` invoked directly |
| 2 | passwordless `sudo -n` | common on dedicated pentest boxes |
| 3 | `$PI_VPN_SUDO_PASS` | for automation; fed via `sudo -S` |
| 4 | in-session UI prompt | cached **in memory only**, never written to disk |

`sudo -v` is re-checked before each privileged call to refresh the timestamp.

### 3. Credential handling

In priority order:

- explicit `authFile` → used as-is.
- explicit `username`/`password` → a temp file is written with mode `0600`.
- the profile has a bare `auth-user-pass` (detected by scanning the config)
  and no creds were passed → the UI prompts interactively (or errors in
  headless mode with no UI).

Temp auth files are deleted in a `finally` block, so they're removed even if
the connect fails or is cancelled. Passwords are held in a process-scoped
variable and **never** persisted to disk.

### 4. Log monitoring

After launching, the extension polls the log file every 500 ms for up to 60 s,
reading only new bytes since the last poll (handles rotation):

- **Success:** `Initialization Sequence Completed` → also captures
  `TUN/TAP device <dev> opened` to learn the interface name.
- **Failure** (first match wins, mapped to a clear message):
  `AUTH_FAILED`, `private key password verification failed`,
  `Options error:`, `Exiting due to fatal error`,
  `Cannot ioctl TUNSETIFF`, `Inactivity timeout`.
- **Process death:** if the pid dies before success → fail with the matched
  reason or the tail of the log.

### 5. Reattach on restart

On `session_start`, the extension reads `~/.pi/vpn/state.json` (persisted only
while connected). If the recorded pid is still alive (`kill -0`; `EPERM`
counts as alive for root-owned pids), it restores full `connected` state —
including `startTime`, so the elapsed counter picks up where it left off — and
restarts the footer timer. If the pid is dead, it clears state and goes idle.

This is what makes the tunnel feel persistent across agent restarts.

### 6. Tunnel-IP detection

Read-only (no root): prefers `ip -j -4 addr show` (JSON), falling back to
text-parsing `ip -4 addr show`, to find the first `tun|tap|ppp|ovpn*`
interface with an IPv4 address.

---

## Configuration

All optional. Zero config for the common case (interactive UI + passwordless
sudo, or running pi as root).

| Env var | Default | Purpose |
|---------|---------|---------|
| `PI_VPN_SUDO_PASS` | *(unset → prompt)* | sudo password for non-interactive / automation use. Fed via `sudo -S`; cached in memory only. |

Generated state (never committed, created at runtime under `~/.pi/vpn/`):

```
state.json          # persisted ONLY while connected (name, configPath, pid,
                    #   startTime, dev) — mode 0600, deleted on disconnect
logs/<slug>.log     # openvpn log for the current/last connection
pid/<slug>.pid      # openvpn pid file
auth-<rand>.txt     # TEMP auth-user-pass file (0600), deleted after connect
```

> For a fire-and-forget setup on a dedicated box, either run pi as root or add
> a passwordless sudoers rule for `openvpn` — then you'll never be prompted.

---

## Security notes

- **The tunnel outlives pi by design.** This is the whole point for long
  sessions, but it means a forgotten tunnel stays up until you `/vpn
  disconnect` or kill the pid. The footer and `state.json` keep it visible.
- **Passwords are ephemeral.** Held in a process-scoped variable; the only disk
  artifact is a `0600` auth file that exists solely during the `connect` call
  and is removed in `finally`.
- **`state.json` carries no secrets** — only `name`, `configPath`, `pid`,
  `startTime`, `dev`. Written with mode `0600`, deleted on disconnect.
- **Runs with your privileges.** Like all pi packages, this executes code
  (`openvpn`, `sudo`, `ip`, `kill`). There is exactly one source file to audit:
  `extensions/vpn.ts`.
- **OpenVPN config files** are your responsibility — review an `.ovpn` before
  connecting, especially `redirect-gateway` and any embedded scripts.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `sudo password required` / `sudo authentication failed` | Run pi as root, add a passwordless sudoers rule for `openvpn`, or `export PI_VPN_SUDO_PASS=…`. In an interactive session, you'll just be prompted. |
| `authentication failed (check VPN credentials)` | Wrong username/password. The profile has a bare `auth-user-pass`; reconnect with correct creds. |
| `cannot create tun device` | Another tunnel is already up, or no privileges. `/vpn disconnect` first, or check sudo. |
| `connection timed out` (60 s) | Server unreachable, or very slow handshake. Check the log at `~/.pi/vpn/logs/<slug>.log`. |
| Footer says connected but no IP | Tunnel-IP detection uses `ip`; ensure iproute2 is installed. The `dev`/`pid` will still show. |
| Tunnel vanished after pi restart | The openvpn process died while pi was away (server dropped you, reboot, etc.). Reconnect. |
| `openvpn: command not found` | `apt install openvpn` (or your distro's equivalent). |
| Want to fully reset | `/vpn disconnect`, then `rm -rf ~/.pi/vpn/` to clear logs/pid/state. |

---

## License

[MIT](LICENSE) — free to use, modify, and distribute. Attribution appreciated but not required.
