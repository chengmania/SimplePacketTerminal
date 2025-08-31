#!/usr/bin/env python3
"""
SPT.py — Simple Packet Terminal (KISS + AX.25)

- Light blue prompt (TTY only).
- Clears screen on start and again upon successful connect (UA).
- Pager-friendly: handles "<A>bort, <CR> Continue..>" prompts (Enter continues, 'A' aborts).
- Helpful commands & aliases:
    /c or /connect CALL [via DIGI1,DIGI2]
    /d or /disconnect
    /q or /quit or /exit
    /h or /help   (/help -v for verbose)
    /clear or /cls
    /status | /echo on|off | /crlf on|off | /debug
- Unproto:
    * One-shot:    /unproto DEST [via DIGI1,DIGI2] message...
    * Persistent:  /unproto DEST [via DIGI1,DIGI2]   (no message -> enters mode)
                   Type /ex to exit unproto mode.
"""
import socket, sys, threading, time, datetime
import re, os

# ---------- Pager prompt patterns ----------
PROMPT_PATTERNS = [
    re.compile(r"<\s*A\s*>?bort,\s*<\s*CR\s*>\s*Continue\.\.?>", re.I),
    re.compile(r"press\s*<\s*cr\s*>\s*to\s*continue", re.I),
]

# ---------- Config ----------
KISS_HOST_DEFAULT = "127.0.0.1"
KISS_PORT_DEFAULT = 8001          # Direwolf: KISSPORT 8001
DEBUG = False

# ---------- KISS constants ----------
FEND  = 0xC0
FESC  = 0xDB
TFEND = 0xDC
TFESC = 0xDD
KISS_DATA = 0x00                  # port 0 data

# ---------- AX.25 control constants (mod-8) ----------
CTRL_SABM = 0x2F                  # P/F bit may be set (0x10)
CTRL_UA   = 0x63
CTRL_DISC = 0x43
CTRL_DM   = 0x0F
CTRL_FRMR = 0x87
CTRL_UI   = 0x03                  # Unnumbered Information (UI)

S_RR  = 0x01
S_RNR = 0x05
S_REJ = 0x09

PID_NO_L3 = 0xF0                  # "text" payload

def dprint(*a):
    if DEBUG: print("[DBG]", *a)

# ---------- Color helpers ----------
def _supports_ansi() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb" and "NO_COLOR" not in os.environ

PROMPT_COLOR = "\033[96m"  # bright cyan (nice on black)
RESET_COLOR  = "\033[0m"

def colorize(s: str) -> str:
    return (PROMPT_COLOR + s + RESET_COLOR) if _supports_ansi() else s

def clear_screen():
    if _supports_ansi():
        sys.stdout.write("\033[2J\033[H")
    else:
        sys.stdout.write("\n" * 40)
    sys.stdout.flush()

# ---------- Callsign <-> AX.25 helpers ----------
def parse_call(call: str):
    call = call.upper().strip()
    if "-" in call:
        base, ssid = call.split("-", 1)
        ssid = int(ssid or "0")
    else:
        base, ssid = call, 0
    return base, ssid

def ax25_addr_bytes(call: str, last: bool, command: bool):
    """
    7 bytes: 6 shifted ASCII + SSID.
    Bit0 of final (7th) byte = 1 if last address in list.
    """
    base, ssid = parse_call(call)
    base = (base + "      ")[:6]  # pad/truncate to 6
    b = bytearray(7)
    for i, ch in enumerate(base):
        b[i] = (ord(ch) << 1) & 0xFE
    ssid_byte = 0x60 | ((ssid & 0x0F) << 1)
    if command:
        ssid_byte |= 0x80
    if last:
        ssid_byte |= 0x01
    b[6] = ssid_byte
    return bytes(b)

def build_ax25_header(dest: str, src: str, digis=None, cmd=True):
    """
    Two-address + optional digipeaters.
    cmd=True sets C bit appropriately on dest/src for the initial command.
    """
    digis = digis or []
    parts = [
        ax25_addr_bytes(dest, last=False, command=cmd),
        ax25_addr_bytes(src,  last=(len(digis) == 0), command=not cmd),
    ]
    for i, d in enumerate(digis):
        parts.append(ax25_addr_bytes(d, last=(i == len(digis) - 1), command=False))
    return b"".join(parts)

def decode_addrs(frame: bytes):
    # Return (dest, src, idx_after_addresses). Handles optional digis.
    if len(frame) < 14: return ("", "", 0)
    def decode7(b):
        call = "".join(chr((b[i] >> 1) & 0x7F) for i in range(6)).rstrip()
        ssid = (b[6] >> 1) & 0x0F
        return f"{call}-{ssid}"
    dest = decode7(frame[0:7])
    src  = decode7(frame[7:14])
    last = frame[13] & 0x01
    i = 14
    if not last:
        while i + 7 <= len(frame):
            if frame[i+6] & 0x01:
                i += 7
                break
            i += 7
    return dest, src, i

def print_banner(mycall: str, host: str, port: int):
    print(BANNER)
    print(f"⟨KISS⟩ Using {host}:{port}  |  MYCALL={mycall}\n")

# ---------- KISS framing ----------
def kiss_escape(payload: bytes) -> bytes:
    payload = payload.replace(bytes([FESC]), bytes([FESC, TFESC]))
    payload = payload.replace(bytes([FEND]), bytes([FESC, TFEND]))
    return payload

def kiss_unescape(payload: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(payload):
        b = payload[i]
        if b == FESC and i+1 < len(payload):
            nxt = payload[i+1]
            if nxt == TFEND: out.append(FEND)
            elif nxt == TFESC: out.append(FESC)
            else: out.append(nxt)
            i += 2
        else:
            out.append(b); i += 1
    return bytes(out)

def kiss_wrap_data(port: int, data: bytes) -> bytes:
    return bytes([FEND, (port << 4) | KISS_DATA]) + kiss_escape(data) + bytes([FEND])

# ---------- Minimal LAPB link (mod-8) ----------
class KissLink:
    def __init__(self, host, port, mycall):
        self.host, self.port = host, port
        self.mycall = mycall.upper()
        self.sock = None
        self.alive = False
        self.rx_thread = None
        self.on_line = print
        # AX.25 state
        self.state = "DISCONNECTED"   # DISCONNECTED, AWAIT_UA, CONNECTED
        self.dest = None
        self.vs = 0                   # next send seq
        self.vr = 0                   # next expected recv seq
        self.appbuf = ""              # buffer partial text lines
        self.digis = []
        # QoL
        self.local_echo = False
        self.tx_newline = "\r"        # or "\r\n"
        # Keepalive
        self._ka_alive = False
        self._ka_thread = None
        self.more_prompt_pending = False
        self.ui_lock = threading.Lock()    # serialize stdout writes a bit
        # Unproto state
        self.unproto_mode = False
        self.unproto_dest = None
        self.unproto_digis = []
        # UI hook to clear & print header when we connect
        self.on_connected_ui = None   # set by run()

    # ----- socket lifecycle -----
    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=5)
        self.sock.settimeout(0.2)
        self.alive = True
        self.rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self.rx_thread.start()
        self.on_line(f"[KISS] Connected to {self.host}:{self.port}")
        self._ka_alive = True
        self._ka_thread = threading.Thread(target=self._ka_loop, daemon=True)
        self._ka_thread.start()

    def close(self):
        self.alive = False
        self._ka_alive = False
        try:
            if self.sock:
                self.sock.close()
        except:
            pass
        self.sock = None

    # ----- AX.25 frame TX helpers -----
    def _send_ax25(self, raw: bytes, port=0):
        frame = kiss_wrap_data(port, raw)
        self.sock.sendall(frame)
        dprint("TX", raw.hex())

    def _send_sabm(self, dest):
        hdr = build_ax25_header(dest, self.mycall, self.digis)
        ctrl = CTRL_SABM | 0x10       # set P bit
        self._send_ax25(hdr + bytes([ctrl]))

    def _send_disc(self):
        if not self.dest: return
        hdr = build_ax25_header(self.dest, self.mycall, self.digis)
        ctrl = CTRL_DISC | 0x10
        self._send_ax25(hdr + bytes([ctrl]))

    def _send_rr(self, pf=0):
        if not self.dest: return
        hdr = build_ax25_header(self.dest, self.mycall, self.digis)
        ctrl = (S_RR | ((self.vr & 0x07) << 5))
        if pf:  # mirror peer's poll with Final
            ctrl |= 0x10
        self._send_ax25(hdr + bytes([ctrl]))

    def _send_i(self, text: bytes):
        if not self.dest or self.state != "CONNECTED": return
        hdr = build_ax25_header(self.dest, self.mycall, self.digis)
        ctrl = ((self.vs & 0x07) << 1) | ((self.vr & 0x07) << 5)  # PF=0
        self.vs = (self.vs + 1) & 7
        pkt = hdr + bytes([ctrl, PID_NO_L3]) + text
        self._send_ax25(pkt)

    def _send_ui(self, dest: str, message: bytes, digis=None):
        """Send an unconnected UI frame (PID F0) to dest (with optional digis)."""
        digis = digis or []
        hdr = build_ax25_header(dest.upper(), self.mycall, digis)
        ctrl = CTRL_UI  # UI frame, PF=0
        pkt = hdr + bytes([ctrl, PID_NO_L3]) + message
        self._send_ax25(pkt)

    # ----- Public ops -----
    def call(self, dest):
        self.dest = dest.upper()
        self.vs = 0; self.vr = 0
        self.state = "AWAIT_UA"
        self._send_sabm(self.dest)
        self.on_line(f"[LINK] Calling {self.dest}" + (f" via {','.join(self.digis)}" if self.digis else "") + " …")

    def disconnect(self):
        if self.state == "CONNECTED":
            self._send_disc()
        self.state = "DISCONNECTED"
        self.dest = None
        self.appbuf = ""
        self.on_line(f"[LINK] Disconnected.")

    def send_text(self, line: str):
        wire = (line + self.tx_newline).encode("utf-8")
        if self.local_echo:
            self.on_line("> " + line)
        self._send_i(wire)

    def send_unproto(self, dest: str, message: str, digis=None):
        wire = message.encode("utf-8", errors="replace")
        self._send_ui(dest, wire, digis=digis or [])
        via = f" via {','.join(digis)}" if digis else ""
        self.on_line(f"[UNPROTO] {dest}{via} :: {message}")

    # ----- Keepalive -----
    def _ka_loop(self):
        while self._ka_alive:
            if self.state == "CONNECTED":
                self._send_rr(pf=1)  # polite poll every minute
            time.sleep(60)

    # ----- RX path -----
    def _rx_loop(self):
        buf = bytearray()
        while self.alive:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            except Exception:
                break
            if not chunk:
                break
            buf.extend(chunk)

            # KISS frame extraction
            while True:
                try:
                    start = buf.index(FEND)
                except ValueError:
                    buf.clear(); break
                try:
                    end = buf.index(FEND, start+1)
                except ValueError:
                    if start > 0:
                        del buf[:start]
                    break

                frame = bytes(buf[start+1:end])  # excludes both FEND
                del buf[:end+1]

                if not frame:
                    continue
                port_type = frame[0]
                typ = port_type & 0x0F
                if typ != KISS_DATA:
                    continue
                raw = kiss_unescape(frame[1:])
                if not raw:
                    continue
                self._handle_ax25(raw)

        self.alive = False

    def _check_more_prompt(self, text: str):
        t = text.strip()
        for pat in PROMPT_PATTERNS:
            if pat.search(t):
                self.more_prompt_pending = True
                return
        if t:
            self.more_prompt_pending = False

    def _send_ua(self, final=1):
        if not self.dest:
            return
        hdr = build_ax25_header(self.dest, self.mycall, self.digis, cmd=False)
        ctrl = CTRL_UA | (0x10 if final else 0)
        self._send_ax25(hdr + bytes([ctrl]))

    def _handle_ax25(self, raw: bytes):
        dprint("RX", raw.hex())
        dest, src, i = decode_addrs(raw)
        if i == 0 or i >= len(raw):
            return
        ctrl = raw[i]

        # I-frame
        if (ctrl & 0x01) == 0:
            ns = (ctrl >> 1) & 0x07
            pf_in = 1 if (ctrl & 0x10) else 0
            if i+1 >= len(raw): return
            info = raw[i+2:]

            if ns == self.vr:
                self.vr = (self.vr + 1) & 7
                self._send_rr(pf=pf_in)

                chunk = info.decode("utf-8", errors="replace")
                chunk = chunk.replace("\r\n", "\n").replace("\r", "\n")
                self.appbuf += chunk

                while "\n" in self.appbuf:
                    line, self.appbuf = self.appbuf.split("\n", 1)
                    self.on_line(line.rstrip())
                    self._check_more_prompt(line)

                if pf_in and self.appbuf:
                    flushed = self.appbuf
                    self.on_line(flushed.rstrip())
                    self._check_more_prompt(flushed)
                    self.appbuf = ""
            else:
                self._send_rr(pf=0)
            return

        base = ctrl & 0xEF  # ignore P/F bit for type compare

        # U-frames
        if base == CTRL_UA:
            if self.state == "AWAIT_UA":
                self.state = "CONNECTED"
                # Clear screen and reprint header/commands before node text
                if callable(self.on_connected_ui):
                    self.on_connected_ui()
                self.on_line(f"[LINK] CONNECTED to {self.dest}")
            return
        if base == CTRL_DM:
            self.on_line("[LINK] Disconnected mode (DM) from peer).")
            self.state = "DISCONNECTED"
            self.dest = None
            self.appbuf = ""
            return
        if base == CTRL_FRMR:
            self.on_line("[LINK] FRMR (frame reject) from peer.")
            return
        if base == CTRL_DISC:
            pf_in = 1 if (ctrl & 0x10) else 0
            self._send_ua(final=pf_in or 1)
            self.state = "DISCONNECTED"
            self.dest = None
            self.appbuf = ""
            self.on_line("[LINK] Peer requested DISC.")
            return

        # S-frames
        s_code = ctrl & 0x0F
        if s_code in (S_RR, S_RNR, S_REJ):
            return

# ---------- Terminal UI ----------
BANNER = (
    "SPT — Simple Packet Terminal\n"
    "An open-source KISS/AX.25 terminal for amateur radio.\n"
    "Created by Chengmania (KC3SMW).\n"
    "\n"
    "• Works with Direwolf (KISS TCP)\n"
    "• Clean, pager-friendly display and colored prompt\n"
    "• Connected mode (/connect) and UNPROTO (UI) frames\n"
    "\n"
    "Type /help for a quick command list, or /help -v for details.\n"
)

HELP_BRIEF = ("Commands: /c|/connect CALL [via DIGI1,DIGI2] | "
              "/d|/disconnect | /q|/quit|/exit | /h|/help [-v] | "
              "/status | /echo on|off | /crlf on|off | /clear|/cls | "
              "/unproto DEST [via DIGI1,DIGI2] [msg...] | /ex")

HELP_VERBOSE = """\
SPT — Simple Packet Terminal (commands)

USAGE
  SPT.py MYCALL [TARGET] [HOST] [PORT]
  SPT.py MYCALL TARGET HOST:PORT

LINK COMMANDS
  /c CALL [via DIGI1,DIGI2]
  /connect CALL [via DIGI1,DIGI2]
      Establish an AX.25 connected (LAPB) session to CALL. Optional digipeaters
      can be provided as a comma-separated list after 'via'.
      Example: /c KC3SMW-7 via WIDE1-1,WIDE2-1

  /d
  /disconnect
      Politely request disconnect (DISC). Prompt updates immediately.

  /q
  /quit
  /exit
      Exit the program. If connected, SPT sends DISC first.

SCREEN & HELP
  /clear
  /cls
      Clear the screen and reprint the header and command summary.

  /h
  /help
      Show the one-line command summary.

  /help -v
      Show this detailed help.

STATUS & SETTINGS
  /status
      Show link state, destination, sequence numbers, digi path and I/O options.

  /debug
      Toggle debug logging of raw frames.

  /echo on|off
      Locally echo what you type as it is transmitted.

  /crlf on|off
      Choose line ending for transmitted text. ON = CRLF (\\r\\n), OFF = CR (\\r).
      Many packet nodes expect just CR.

UNCONNECTED (UI) FRAMES
  /unproto DEST [via DIGI1,DIGI2] message...
      Send an AX.25 UI frame (PID F0) to DEST, optionally via digipeaters.

  /unproto DEST [via DIGI1,DIGI2]
      Enter persistent UNPROTO mode to DEST (and optional digis). Every line
      that doesn't start with '/' will be sent as a UI frame. Use /ex to exit.

  /ex
      Exit persistent UNPROTO mode.

PAGER PROMPTS
  When the BBS shows: "<A>bort, <CR> Continue..>"
    - Press Enter to continue (SPT sends a bare CR)
    - Type 'A' (upper or lower) to abort
"""

def run(mycall, target, host, port):
    link = KissLink(host, port, mycall)
    clear_screen()
    print_banner(mycall, host, port)
    logf = open(f"session-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.log", "w", buffering=1)

    # --- header printer used at start & on UA & by /clear ---
    def print_header():
        print(f"⟨KISS AX.25 Terminal⟩ MYCALL={mycall}  KISS={host}:{port}")
        print(HELP_BRIEF)

    def ui_clear_and_header():
        clear_screen()
        print_header()

    # --- dynamic prompt builder with color ---
    def prompt() -> str:
        if link.state == "CONNECTED" and link.dest:
            core = f"[{mycall.upper()} @ {link.dest}] >> "
        else:
            core = f"[{mycall.upper()}] >> "
        return colorize(core)

    # --- incoming lines: overwrite current input line, then redraw prompt ---
    def emit(s: str):
        try:
            logf.write(s + "\n")
        except Exception:
            pass
        with link.ui_lock:
            if _supports_ansi():
                sys.stdout.write("\r\033[2K" + s + "\n")
                sys.stdout.write("\033[2K" + prompt())
            else:
                sys.stdout.write("\r" + s + "\n" + prompt())
            sys.stdout.flush()

    link.on_line = emit
    link.on_connected_ui = ui_clear_and_header
    link.connect()
    print_header()
    if target:
        print(f"Tip: /c {target}")

    try:
        while True:
            sys.stdout.write(prompt())
            sys.stdout.flush()

            line = sys.stdin.readline()
            if not line:
                break
            line = line.rstrip("\n")
            cmd = line.strip()
            low = cmd.lower()
            toks = low.split()
            ftok = toks[0] if toks else ""

            # Unproto persistent mode: non-command lines go to UI frames
            if cmd and not cmd.startswith("/") and link.unproto_mode and link.unproto_dest:
                link.send_unproto(link.unproto_dest, cmd, link.unproto_digis)
                continue

            # Empty line: maybe pager continue
            if not cmd:
                if getattr(link, "more_prompt_pending", False):
                    link.send_text("")          # sends just CR/CRLF per your setting
                    link.more_prompt_pending = False
                continue

            # Abort hotkey during pager
            if getattr(link, "more_prompt_pending", False) and low == "a":
                link.send_text("A")
                link.more_prompt_pending = False
                continue

            # quit / exit
            if ftok in ("/q", "/quit", "/exit"):
                link.disconnect()
                break

            # disconnect
            if ftok in ("/d", "/disconnect"):
                link.disconnect()
                # force prompt repaint
                sys.stdout.write("\r\033[2K" + prompt())
                sys.stdout.flush()
                continue

            # connect
            if ftok in ("/c", "/connect"):
                parts = cmd.split()
                dest = parts[1] if len(parts) > 1 else (target or "")
                digis = []
                if len(parts) >= 4 and parts[2].lower() == "via":
                    digis = [d.strip().upper() for d in parts[3].split(",") if d.strip()]
                if not dest:
                    print("Usage: /connect <DEST> [via DIGI1,DIGI2]")
                    continue
                link.digis = digis
                link.call(dest)
                continue

            # clear screen
            if ftok in ("/clear", "/cls"):
                ui_clear_and_header()
                continue

            # unproto
            if ftok == "/unproto":
                # /unproto DEST [via DIGI1,DIGI2] [message...]
                ups = cmd.split()
                if len(ups) < 2:
                    print("Usage: /unproto DEST [via DIGI1,DIGI2] [message...]")
                    continue
                dest = ups[1].upper()
                digis = []
                msg = ""
                via_idx = None
                for i, t in enumerate(ups):
                    if t.lower() == "via":
                        via_idx = i; break
                if via_idx is not None:
                    if via_idx + 1 < len(ups):
                        digis = [d.strip().upper() for d in ups[via_idx+1].split(",") if d.strip()]
                    if via_idx + 2 < len(ups):
                        msg = " ".join(ups[via_idx+2:])
                else:
                    if len(ups) >= 3:
                        msg = " ".join(ups[2:])

                if msg:
                    link.send_unproto(dest, msg, digis)
                else:
                    link.unproto_mode = True
                    link.unproto_dest = dest
                    link.unproto_digis = digis
                    via = f" via {','.join(digis)}" if digis else ""
                    print(f"[UNPROTO] Persistent mode ON -> {dest}{via}. Type /ex to exit.")
                continue

            if ftok == "/ex":
                if link.unproto_mode:
                    link.unproto_mode = False
                    link.unproto_dest = None
                    link.unproto_digis = []
                    print("[UNPROTO] Persistent mode OFF.")
                else:
                    print("[UNPROTO] Not in unproto mode.")
                continue

            # status
            if ftok == "/status":
                echo_on = "on" if getattr(link, "local_echo", True) else "off"
                crlf_on = "on" if getattr(link, "tx_newline", "\r") == "\r\n" else "off"
                up = "on" if link.unproto_mode else "off"
                up_to = link.unproto_dest or "(none)"
                up_via = ",".join(link.unproto_digis) if link.unproto_digis else "[]"
                print(f"[STATUS] state={link.state} dest={link.dest or '(none)'} vs={link.vs} vr={link.vr} "
                      f"digis={link.digis or '[]'} echo={echo_on} crlf={crlf_on} "
                      f"unproto={up} to={up_to} via={up_via}")
                continue

            # debug
            if ftok == "/debug":
                global DEBUG
                DEBUG = not DEBUG
                print(f"[DEBUG] {'ON' if DEBUG else 'OFF'}")
                continue

            # echo
            if ftok == "/echo":
                if len(toks) == 2 and toks[1] in ("on", "off"):
                    link.local_echo = (toks[1] == "on")
                    print(f"[ECHO] {'ON' if link.local_echo else 'OFF'}")
                else:
                    print("Usage: /echo on|off")
                continue

            # crlf
            if ftok == "/crlf":
                if len(toks) == 2 and toks[1] in ("on", "off"):
                    link.tx_newline = "\r\n" if toks[1] == "on" else "\r"
                    print(f"[CRLF] {'ON (\\r\\n)' if link.tx_newline=='\\r\\n' else 'OFF (\\r)'}")
                else:
                    print("Usage: /crlf on|off")
                continue

            # help
            if ftok in ("/h", "/help"):
                if "-v" in toks or "verbose" in toks:
                    print(HELP_VERBOSE)
                else:
                    print(HELP_BRIEF)
                continue

            # Unknown slash command -> "no ***"
            if cmd.startswith("/"):
                print("command not found use /h for list of commands")
                continue

            # Otherwise, send user text on the connected link
            link.send_text(line)
            try:
                logf.write("> " + line + "\n")
            except Exception:
                pass

    except KeyboardInterrupt:
        pass
    finally:
        try:
            logf.close()
        except Exception:
            pass
        link.close()
        print("\n⟨KISS AX.25 Terminal⟩ bye.")

# ---------- CLI parsing ----------
def _looks_like_host(s: str) -> bool:
    return s == "localhost" or "." in s or ":" in s

if __name__ == "__main__":
    # Accepted forms:
    #   SPT.py MYCALL
    #   SPT.py MYCALL TARGET
    #   SPT.py MYCALL TARGET HOST
    #   SPT.py MYCALL TARGET HOST PORT
    #   SPT.py MYCALL TARGET 0 HOST PORT        # legacy RF port ignored
    #   SPT.py MYCALL TARGET HOST:PORT
    args = sys.argv[1:]
    if len(args) < 1:
        print(f"Usage: {sys.argv[0]} MYCALL [TARGET] [HOST] [PORT]")
        print(f"   or: {sys.argv[0]} MYCALL TARGET HOST:PORT")
        sys.exit(1)

    mycall = args[0]
    target = None
    host = KISS_HOST_DEFAULT
    port = KISS_PORT_DEFAULT

    i = 1
    # Optional TARGET (skip if the next token looks like a host or a number-only legacy arg)
    if i < len(args) and not _looks_like_host(args[i]) and not args[i].isdigit():
        target = args[i]; i += 1

    # Legacy optional RF port (ignore it if present)
    if i < len(args) and args[i].isdigit():
        i += 1  # ignore

    # Optional HOST[:PORT]
    if i < len(args):
        hp = args[i]; i += 1
        if ":" in hp:
            h, p = hp.split(":", 1)
            if h: host = h
            try:
                port = int(p)
            except ValueError:
                pass
        elif _looks_like_host(hp):
            host = hp

    # Optional PORT
    if i < len(args):
        try:
            port = int(args[i])
        except ValueError:
            pass

    run(mycall, target, host, port)
