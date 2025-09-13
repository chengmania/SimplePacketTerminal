# Simple Packet Terminal (SPT)

**SPT** is a tiny, cross-platform **KISS + AX.25** terminal for amateur packet radio.
It talks to **Direwolf** (or any KISS-TCP TNC), gives you a clean color prompt, handles
BBS **pager** prompts gracefully, and supports both **connected** AX.25 and **UNPROTO (UI)** frames.

Created by **Chengmania (KC3SMW)**. Free & open source, without warranty.

---

## Highlights

- ✅ **Direwolf KISS-TCP** compatible (default `127.0.0.1:8001`)
- ✅ **Connected mode** (SABME/SABM handshake, RR keepalives, DISC/UA handling)
- ✅ **UNPROTO (UI) frames** — one-shot or persistent mode, with **digipeater paths**
- ✅ **Pager detection** — smart regex + rolling buffer; `Enter` continues, `A` aborts
- ✅ **Colorized UI** — distinct **prompt color** and **RX text color** (new in v0.9a)
- ✅ **/color** command — change colors at runtime (e.g., `/color rx brightyellow`)
- ✅ **Clear screens & banner** on start and on connect
- ✅ **Status, history, logs** — `/status`, readline history, per-session log files
- ✅ **Retries control** — `/retries N` for handshake attempts
- ✅ **BBS-friendly** — unknown slash commands are forwarded when connected

---

## Requirements

- Python **3.8+**
- A KISS-TCP TNC (e.g., **Direwolf**). Default: `127.0.0.1:8001`
- A terminal that supports ANSI colors (optional but nice)

---

# Quick Start


### Clone
`git clone https://github.com/chengmania/SimplePacketTerminal.git
cd SimplePacketTerminal`

### Run (basic)
`python3 SPT_0_9a.py KC3SMW`

### Run and show a tip to connect to a target call
`python3 SPT_0_9a.py KC3SMW KC3SMW-7`

### Custom KISS host/port
`python3 SPT_0_9a.py KC3SMW KC3SMW-7 127.0.0.1 8001`
### or:
`python3 SPT_0_9a.py KC3SMW KC3SMW-7 127.0.0.1:8001`


### Common Commands
`
/c | /connect CALL [via DIGI1,DIGI2]   Connect (AX.25)
/d | /disconnect                       Disconnect
/unproto DEST [via DIGI1,DIGI2] [msg]  UI frame; no msg -> persistent mode
/upexit                                 Exit persistent unproto mode
/echo on|off                            Local echo
/crlf on|off                            Send CRLF instead of CR
/retries N                              Set connect retries (default 3)
/debug                                  Toggle debug logging
/clear | /cls                           Clear screen
/status                                 Show link status
/color rx <name>|prompt <name>          Set RX/prompt color (e.g., brightyellow)
/h | /help [-v]                         Show help (use -v for verbose)
/q | /quit | /exit                      Quit`

### Color Names (for /color)

`black, red, green, yellow, blue, magenta, cyan, white, brightblack, brightred, brightgreen, brightyellow, brightblue, brightmagenta, brightcyan, brightwhite, none`

Examples:
`/color rx brightyellow
/color prompt magenta
/color rx none`

Default colors (v0.9a):
Prompt: bright cyan (\033[96m)
RX text: bright green (\033[92m)


Connect (no digis)
`/connect KC3SMW-7`

Connect via digipeaters
`/connect KC3SMW-7 via WIDE1-1,WIDE2-1`


One-shot UNPROTO
`/unproto CQ Hello from SPT`

Persistent UNPROTO (type to send UI frames every line)
`/unproto CQ
... your lines are sent as UI frames ...
/upexit`



## Tips

Queued input during handshake: If you start typing before the link is up,
SPT queues your plain text and flushes it after UA/connect.
CR vs CRLF: Some nodes want \r\n. Use /crlf on.
History file: ~/.spt_history (if your Python has readline).
Session logs: session-YYYYMMDD-HHMMSS.log in the working directory.



### Troubleshooting

+No connect / UA: Try increasing /retries 5 and reattempt. Make sure Direwolf is listening on KISS TCP port 8001.

+Colors look off: Your terminal theme may remap ANSI colors. Try /color rx brightyellow or /color rx none.

+Pager stuck: Tap Enter to advance; A to abort. If your BBS uses unusual prompts, send me a sample so we can add patterns.



### Changelog
v0.9a

*NEW: RX text coloring (separate from prompt)
*NEW: /color rx|prompt <name> to change colors at runtime
*Improved: Pager detection (regex + rolling buffer) and state handling
*Improved: Keepalives pause while pager prompts are pending
*UI: Clear startup and connected banners; better status readout
*UNPROTO: Cleaner digipeater handling for both one-shot and persistent modes
*Link: SABME→SABM fallback, DM/FRMR handling, retry control via /retries

v0.9
First polished 0.9 with pager fixes, better help, improved UI, connect/disconnect handling
