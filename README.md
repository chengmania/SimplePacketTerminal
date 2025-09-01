# SPT — Simple Packet Terminal

SPT is a tiny, cross-platform **KISS + AX.25** terminal for amateur packet radio.  
It speaks to **Direwolf** over TCP KISS, gives you a clean, colorized prompt, handles BBS “more” prompts gracefully, and supports both **connected** AX.25 and **UNPROTO (UI)** frames.

Created by **Chengmania (KC3SMW)**. Open source and hackable.

---

## Why SPT?

- **Dead simple:** one file, no external Python packages.
- **Fast start:** point it at Direwolf’s KISS TCP port and go.
- **Friendly TTY UX:** light-blue prompt, clean redraws, and pager awareness.
- **Real work flows:** connect to nodes/BBSs or chat unconnected via UNPROTO.
- **Portable:** Linux, macOS, Windows (PowerShell/Windows Terminal).

---

## Features

- KISS TCP client for Direwolf
- AX.25 LAPB (mod-8): SABM/UA/DISC, I-frames, RR (keepalive)
- Pager awareness for BBS prompts like:  
- Colorized prompt: `[MYCALL @ PEER] >>` (TTY only)
- Logs each session to `session-YYYYMMDD-HHMMSS.log`
- **UNPROTO (UI) support:**
  - One-shot `/unproto DEST [via DIGI1,DIGI2] message…`
  - Persistent UNPROTO mode until `/ex`
- Screen clear on start and on connect; quick `/clear` or `/cls`
- Helpful command help (brief + verbose)

---

## Requirements

- **Python**: 3.8+ (standard library only; no `pip install` needed)
- **Direwolf** (with KISS TCP enabled)
  - Linux/macOS: use your package manager (`brew install direwolf` on macOS)
  - Windows: run Direwolf and allow it through the firewall on first use

> **Note (Windows-only):** If you use legacy `cmd.exe` and ANSI colors don’t display, you can optionally `pip install colorama` and enable it in the script. In Windows Terminal/PowerShell, no changes are needed.

---

## Configure Direwolf

Make sure your `direwolf.conf` exposes a TCP KISS port, e.g.:

```
# Example
KISSPORT 8001
```

Start Direwolf, confirm it prints something like:

```
Ready to accept KISS TCP client application 0 on port 8001 ...
```

---

## Install

Just copy **SPT.py** into it's own folder and run it.  
No Python dependencies required.

---

## Usage

```
python3 SPT.py MYCALL [TARGET] [HOST] [PORT]
python3 SPT.py MYCALL TARGET HOST:PORT
```

**Arguments (all optional after `MYCALL`):**
- `TARGET` — station to auto-connect on startup (e.g., `KC3SMW-7`)
- `HOST` & `PORT` — Direwolf KISS TCP (defaults: `127.0.0.1:8001`)
- Legacy numeric RF port args are ignored for convenience.

**Examples**
```bash
# Connect to a local Direwolf (127.0.0.1:8001) and just idle
python3 SPT.py KC3SMW-0

# Same, but auto connect to a node
python3 SPT.py KC3SMW-0 KC3SMW-7

# Explicit host/port
python3 SPT.py KC3SMW-0 KC3SMW-7 127.0.0.1 8001

# Host:Port shorthand
python3 SPT.py KC3SMW-0 KC3SMW-7 127.0.0.1:8001
```

---

## Command Reference

**Brief:**  
`Commands: /(c)onnect CALL [via DIGI1,DIGI2] | /(d)isconnect | /(q)uit | /(h)elp | /status | /debug | /echo on|off | /crlf on|off | /clear | /unproto DEST [via DIGI1,DIGI2] [message…] | /ex`

**Details (concise):**

- `/(c)onnect CALL [via DIGI1,DIGI2]`  
  Start a connected AX.25 session to `CALL`. Optional digis are comma-separated.

- `/(d)isconnect`  
  Send DISC and immediately return to idle prompt.

- `/(q)uit`, `/quit`, `/exit`  
  Exit SPT (sends DISC first if connected).

- `/(h)elp`  
  Show the brief command list.  
  `/help -v` shows a longer explanation.

- `/status`  
  Print link state, peer, VR/VS, digi path, echo/crlf, and UNPROTO mode.

- `/debug`  
  Toggle raw frame debug logging in the console.

- `/echo on|off`  
  Local echo of what you transmit.

- `/crlf on|off`  
  Choose CRLF (`on`) or CR (`off`, default) for transmitted lines.

- `/clear` or `/cls`  
  Clear screen and reprint the brief command list.

- `/unproto DEST [via DIGI1,DIGI2] message…`  
  Send a one-shot **UI** frame (PID F0).  
  Example: `/unproto CQ via WIDE1-1 Hello from SPT`

- `/unproto DEST [via DIGI1,DIGI2]` (no message)  
  Enter **persistent UNPROTO** mode to `DEST` (and digis).  
  Every line that **doesn’t** start with `/` is sent as a UI frame.  
  Use `/ex` to exit persistent UNPROTO mode.

- `/ex`  
  Exit persistent UNPROTO mode.

**Unknown slash commands** print: `no ***`

---

## Pager / “More” Prompts

When a BBS shows something like `"<A>bort, <CR> Continue..>"`:

- Press **Enter** to continue (SPT sends a bare CR or CRLF based on your setting).
- Type `A` (uppercase or lowercase) to abort that page.

SPT detects these lines and won’t spam prompts between screenfuls.

---

## Example Session

```
$ python3 SPT.py KC3SMW-0 KC3SMW-7
[KISS] Connected to 127.0.0.1:8001
Commands: /(c)onnect CALL [via DIGI1,DIGI2] | /(d)isconnect | /(q)uit | /(h)elp | /status | /debug | /echo on|off | /crlf on|off | /clear | /unproto ... | /ex
[KC3SMW-0] >> /c KC3SMW-7
[LINK] Calling KC3SMW-7 …
[LINK] CONNECTED to KC3SMW-7
Welcome to the chengmanian Node...
[KC3SMW-0 @ KC3SMW-7] >> bbs
SMW:KC3SMW-7} Connected to BBS
...
[KC3SMW-0 @ KC3SMW-7] >> bye
[LINK] Peer requested DISC.
[KC3SMW-0] >>
```

---

## Tips

- Many nodes expect **CR** only (`/crlf off`), which is SPT’s default.
- Use `/status` if you’re unsure whether you’re connected or in UNPROTO mode.
- Want quiet TX lines? Keep `/echo off` (default).
- You can enter UNPROTO mode to `CQ` or a friend’s call and chat without connecting.

---

## Troubleshooting

- **Direwolf not reachable:** confirm `KISSPORT` and host/port in SPT match Direwolf’s log line.
- **No audio/TX/RX:** check audio device levels in Direwolf; most stations should peak ~50.
- **Colors look wrong on Windows:** prefer Windows Terminal/PowerShell. Legacy `cmd.exe` may need `colorama`.
- **BBS paging locks input:** Hitting **Enter** or `A` should advance; if you typed a command mid-page, wait for the next prompt.

---

## Roadmap / Ideas

- Config file for defaults (host/port, CRLF, echo)
- AX.25 extended sequence support (mod-128)
- Optional timestamps and coloring for RX/TX lines
- Auto-reconnect / retry backoff

---

## Contributing

Issues and PRs welcome! Keep the code single-file and dependency-free where possible.

---

## License

Choose a license that fits your goals (MIT is a good default).  
*(Replace this section with your chosen license file.)*

---

## Acknowledgements

- **Direwolf** by John WB2OSZ — the backbone TNC for this project.  
- Everyone running packet nodes and BBSs that make testing and real use possible. 73!
