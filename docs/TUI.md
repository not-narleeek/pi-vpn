# The `pi-vpn` TUI

A standalone, keyboard-driven terminal UI for managing OpenVPN connections —
no pi, no agent required. Drop it in a tmux pane and drive your CTF / lab VPNs
with a few keystrokes.

```
┌ pi-vpn ─ 14:32:07 ───────────────────────────────────────────────────┐
│ 🔒 htb  ● connected  10.10.14.23  tun0  12:03  pid 4821              │
├──────────────────────────────┬───────────────────────────────────────┤
│ Configs                      │ Log                                   │
│ ▸ ● htb.ovpn                 │ Wed Jul 16 … TCP link …               │
│   ○ thm.ovpn                 │ Wed Jul 16 … Initialization Sequence  │
│   ○ engagement.ovpn          │ Wed Jul 16 … Peer …                   │
│                              │                                       │
├──────────────────────────────┴───────────────────────────────────────┤
│ ↑↓/jk select   ⏎ connect   d disconnect   r refresh   q quit          │
└──────────────────────────────────────────────────────────────────────┘
```

## Install

The binary is built from `tui/vpn-tui.ts` (+ `tui/vpn-core.ts`) and bundled to a
single zero-dependency file.

```bash
git clone https://github.com/not-narleeek/pi-vpn
cd pi-vpn
npm install          # runs the `prepare` script → builds dist/pi-vpn.cjs
npm link             # puts `pi-vpn` on your PATH  (optional)
```

or, without linking:

```bash
node dist/pi-vpn.cjs            # launch the TUI
./dist/pi-vpn.cjs status        # the shebang works directly too
```

> No runtime dependencies — `dist/pi-vpn.cjs` is fully self-contained.
> `esbuild` and `typescript` are build-time (`devDependencies`) only.

## Commands

| Command | What it does |
|---------|--------------|
| `pi-vpn` | Launch the interactive TUI. |
| `pi-vpn <file.ovpn>` | Launch the TUI with a config preselected. |
| `pi-vpn connect <file>` | Connect non-interactively, then exit. |
| `pi-vpn disconnect` | Tear down the current tunnel, then exit. |
| `pi-vpn status` | One-line status (`name status ip dev elapsed config`); exits non-zero if not connected. |
| `pi-vpn list` | Print discovered `.ovpn` files. |

### Connect flags

```
pi-vpn connect htb.ovpn --username norlek --password '*****'
pi-vpn connect htb.ovpn --auth-file ~/.config/htb/auth.txt
```

| Flag | Purpose |
|------|---------|
| `--username <u>` | VPN username (for `auth-user-pass` profiles). |
| `--password <p>` | VPN password. Prefer a prompt or `--auth-file`. |
| `--auth-file <path>` | Existing `auth-user-pass` file (user line 1, pass line 2). |

## Keybindings (inside the TUI)

| Key | Action |
|-----|--------|
| `↑` / `↓` or `k` / `j` | Move selection. |
| `Enter` | Connect to the selected config (switches if one is up). |
| `d` | Disconnect the current tunnel. |
| `r` | Refresh — rescan configs + re-read status/IP. |
| `q` / `Esc` / `Ctrl-C` | Quit (the tunnel keeps running). |

When a profile needs credentials (bare `auth-user-pass`) or sudo isn't
passwordless, the footer becomes a masked input prompt — type and press Enter.

## Responsive layout

The frame is recomputed from the terminal size on every render:

- **Wide (≥ 100 cols)** — status bar on top, **Configs ‖ Log** side by side, keybinds at the bottom.
- **Narrow (< 100 cols)** — **Configs** stacked above **Log**.
- **Tiny** — still renders without overflow; keybinds truncate gracefully.

Resize a tmux pane and the TUI re-renders immediately (it listens for the
terminal `resize` event / `SIGWINCH`).

## tmux friendliness

- Uses the **alternate screen buffer** — your scrollback is preserved.
- **Hides the cursor** while running; restores it on exit.
- Truncates box borders to the real column count (no autowrap flicker).
- **Honors `NO_COLOR`** — set it for colorless logs / piped capture.
- Clean teardown on `q`, `Esc`, `Ctrl-C`, `SIGINT`, `SIGTERM`, `SIGHUP`.

> Tip: keep the TUI in its own persistent pane:
> ```bash
> tmux new-session -d -s vpn 'pi-vpn' && tmux attach -t vpn
> ```
> The tunnel is a detached daemon, so it survives the pane/TUI closing.

## How it works

All VPN logic lives in [`tui/vpn-core.ts`](../tui/vpn-core.ts) — a
framework-agnostic `VpnManager` class plus the privilege model, credential
handling, `.ovpn` discovery, and log monitoring. The TUI
([`tui/vpn-tui.ts`](../tui/vpn-tui.ts)) is purely rendering + terminal handling
+ the CLI argument parser, and imports only from the core.

The behaviour mirrors the pi extension (`extensions/vpn.ts`): connections start
with `openvpn --daemon`, survive pi quitting, and are reattached on startup via
`~/.pi/vpn/state.json` + PID liveness. See [the main README](../README.md) and
[docs/ARCHITECTURE.md](ARCHITECTURE.md) for the full lifecycle.

## Environment

| Var | Purpose |
|-----|---------|
| `PI_VPN_SUDO_PASS` | sudo password for non-interactive use (fed via `sudo -S`). |
| `NO_COLOR` | Disable ANSI color. |

## State on disk

```
~/.pi/vpn/
├── state.json          # persisted only while connected (0600)
├── logs/<slug>.log     # openvpn log
├── pid/<slug>.pid      # openvpn pid file
└── auth-<rand>.txt     # TEMP auth file (0600), deleted after connect
```
