#!/usr/bin/env python3
"""
SPT_0_9a.py - Simple Packet Terminal (KISS + AX.25, mod-8)

Changes in this 'a' build:
- Added per-line RX coloring (I-frame text and RX UI monitor lines)
- Kept prompt color separate from RX color
- Added /color command to change 'prompt' or 'rx' color at runtime
- Non-payload system/link messages keep default terminal color

Based on SPT_0_9.py (KC3SMW)
"""

import socket, sys, threading, time, datetime
import re, os, atexit
from typing import List, Optional

# ---------- Pager prompt patterns ----------
PROMPT_PATTERNS = [
    # Common BBS pager prompts - more flexible patterns
    re.compile(r".*<\s*CR\s*>.*[Cc]ontinue.*", re.I | re.DOTALL),
    re.compile(r".*[Pp]ress.*<\s*CR\s*>.*[Cc]ontinue.*", re.I | re.DOTALL),
    re.compile(r".*<\s*A\s*>.*[Aa]bort.*<\s*CR\s*>.*[Cc]ontinue.*", re.I | re.DOTALL),
    re.compile(r".*\(A\)bort.*\(CR\).*[Cc]ontinue.*", re.I | re.DOTALL),
    re.compile(r".*More\s*\(Y/n\).*", re.I),
    re.compile(r".*--More--.*", re.I),
    re.compile(r".*Press any key.*", re.I),
]

# ---------- Config ----------
KISS_HOST_DEFAULT = "127.0.0.1"
KISS_PORT_DEFAULT = 8001          # Direwolf default
DEBUG = False

# ---------- KISS constants ----------
FEND  = 0xC0
FESC  = 0xDB
TFEND = 0xDC
TFESC = 0xDD
KISS_DATA = 0x00                  # port 0 data

# ---------- AX.25 control constants (mod-8) ----------
CTRL_SABM  = 0x2F                 # v2.0
CTRL_SABME = 0x6F                 # v2.2
CTRL_UA    = 0x63
CTRL_DISC  = 0x43
CTRL_DM    = 0x0F
CTRL_FRMR  = 0x87
CTRL_UI    = 0x03                 # Unnumbered Information (UI)

S_RR  = 0x01
S_RNR = 0x05
S_REJ = 0x09

PID_NO_L3 = 0xF0                  # "text" payload

def dprint(*a):
    if DEBUG: print("[DBG]", *a)

# ---------- Color & screen helpers ----------
def _supports_ansi() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb" and "NO_COLOR" not in os.environ

# Make these variables so they can be adjusted at runtime with /color
PROMPT_COLOR = "\033[96m"  # bright cyan
RX_COLOR     = "\033[93m"  # bright green for received lines
RESET_COLOR  = "\033[0m"

def colorize_prompt(s: str) -> str:
    return (PROMPT_COLOR + s + RESET_COLOR) if _supports_ansi() and PROMPT_COLOR else s

def colorize_rx(s: str) -> str:
    return (RX_COLOR + s + RESET_COLOR) if _supports_ansi() and RX_COLOR else s

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

def ax25_addr_bytes(call: str, set_last: bool, command: bool, has_been_repeated: bool = False) -> bytes:
    """Build AX.25 address field with digipeater support"""
    call_up = call.upper().split('-')[0]
    ssid = int(call.split('-')[1]) if '-' in call else 0
    call_up = (call_up + ' ' * 6)[:6]
    b = bytearray(7)
    for i, ch in enumerate(call_up):
        b[i] = (ord(ch) << 1) & 0xFE
    ssid_byte = 0x60 | ((ssid & 0x0F) << 1)
    if command:
        ssid_byte |= 0x80  # C-bit orientation
    if has_been_repeated:
        ssid_byte |= 0x80  # H-bit for digipeaters that have been used
    if set_last:
        ssid_byte |= 0x01
    b[6] = ssid_byte
    return bytes(b)

def build_ax25_header(dest: str, src: str, digis, *, cmd: bool = True) -> bytes:
    """Build address field with explicit Command/Response orientation and digipeater support."""
    digis = digis or []
    parts = [
        ax25_addr_bytes(dest, set_last=False, command=cmd),
        ax25_addr_bytes(src,  set_last=(len(digis) == 0), command=not cmd),
    ]
    for i, d in enumerate(digis):
        # For UI frames through digipeaters, don't set H-bit initially
        parts.append(ax25_addr_bytes(d, set_last=(i == len(digis) - 1), command=False, has_been_repeated=False))
    return b''.join(parts)

def decode_addrs(frame: bytes):
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
        self.sock: Optional[socket.socket] = None
        self.alive = False
        self.rx_thread: Optional[threading.Thread] = None
        self.on_line = print          # generic emitter (system/link msgs)
        self.on_rx_line = None        # NEW: payload emitter (colored)
        # AX.25 state
        self.state = "DISCONNECTED"
        self.dest: Optional[str] = None
        self.vs = 0
        self.vr = 0
        self.appbuf = ""
        self.digis: List[str] = []
        # QoL
        self.local_echo = False
        self.tx_newline = "\r"  # tip: /crlf on if your node prefers CRLF
        # Keepalive
        self._ka_alive = False
        self._ka_thread: Optional[threading.Thread] = None
        self.more_prompt_pending = False
        self.ui_lock = threading.Lock()
        # Unproto state
        self.unproto_mode = False
        self.unproto_dest: Optional[str] = None
        self.unproto_digis: List[str] = []
        # UI hook to clear & print header when we connect
        self.on_connected_ui = None
        # Pending user lines to send after UA
        self._pending_lock = threading.Lock()
        self._pending_after_connect: List[str] = []
        # Connect retries
        self.retries = 3
        self.retry_wait = 2.5  # seconds to wait for UA per attempt
        # Handshake latch to avoid re-SABM storms
        self._ua_event = threading.Event()
        # One-shot fallback latch on DM
        self._dm_fallback_tried = False
        self._recent_tail = ""      # rolling tail of recent rx text (for prompt detection)
        self._recent_tail_max = 512 # keep last N chars - increased for better pattern matching

    # ----- socket lifecycle -----
    def connect(self):
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=5)
            self.sock.settimeout(0.2)
            self.alive = True
            self.rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
            self.rx_thread.start()
            # Completely silent - no output at all during startup
            self._ka_alive = True
            self._ka_thread = threading.Thread(target=self._ka_loop, daemon=True)
            self._ka_thread.start()
        except Exception as e:
            # Only show errors
            if hasattr(self, 'on_line') and self.on_line:
                self.on_line(f"[ERROR] KISS connection failed: {e}")
            else:
                print(f"[ERROR] KISS connection failed: {e}")
            raise

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
        if not self.sock: return
        frame = kiss_wrap_data(port, raw)
        self.sock.sendall(frame)
        dprint("TX", raw.hex())

    def _send_sabm(self, dest):
        hdr = build_ax25_header(dest, self.mycall, self.digis, cmd=True)
        ctrl = CTRL_SABM | 0x10  # P=1
        self._send_ax25(hdr + bytes([ctrl]))

    def _send_sabme(self, dest):
        hdr = build_ax25_header(dest, self.mycall, self.digis, cmd=True)
        ctrl = CTRL_SABME | 0x10  # P=1
        self._send_ax25(hdr + bytes([ctrl]))

    def _send_disc(self):
        if not self.dest: return
        hdr = build_ax25_header(self.dest, self.mycall, self.digis, cmd=True)
        ctrl = CTRL_DISC | 0x10  # P=1
        self._send_ax25(hdr + bytes([ctrl]))

    def _send_rr(self, is_command: bool, pf: int):
        """Send RR as command (poll) or response (final). n(r) = vr; do NOT advance vr here."""
        if not self.dest: return
        hdr = build_ax25_header(self.dest, self.mycall, self.digis, cmd=is_command)
        ctrl = (S_RR | ((self.vr & 0x07) << 5))  # n(r)=vr
        if pf:
            ctrl |= 0x10  # P when command, F when response
        self._send_ax25(hdr + bytes([ctrl]))

    def _send_ua(self, final=1):
        if not self.dest: return
        hdr = build_ax25_header(self.dest, self.mycall, self.digis, cmd=False)  # response
        ctrl = CTRL_UA | (0x10 if final else 0)
        self._send_ax25(hdr + bytes([ctrl]))

    def _send_i(self, text: bytes):
        if not self.dest or self.state != "CONNECTED": return
        hdr = build_ax25_header(self.dest, self.mycall, self.digis, cmd=True)
        ctrl = ((self.vs & 0x07) << 1) | ((self.vr & 0x07) << 5)
        self.vs = (self.vs + 1) & 7
        pkt = hdr + bytes([ctrl, PID_NO_L3]) + text
        self._send_ax25(pkt)

    def _send_ui(self, dest: str, message: bytes, digis=None):
        """Send UI frame with proper digipeater support"""
        digis = digis or []
        # For UI frames, use command=True to ensure proper C-bit setting
        hdr = build_ax25_header(dest.upper(), self.mycall, digis, cmd=True)
        ctrl = CTRL_UI
        pkt = hdr + bytes([ctrl, PID_NO_L3]) + message
        self._send_ax25(pkt)

    def _update_recent_tail(self, s: str):
        """Update the rolling tail buffer used for pager detection"""
        if not s:
            return
        self._recent_tail = (self._recent_tail + s)[-self._recent_tail_max:]

    def _detect_pager_prompt(self, text: str = None) -> bool:
        """Improved pager detection with better pattern matching"""
        if text:
            # Check the specific text first
            test_text = text.strip()
            if test_text:
                for pat in PROMPT_PATTERNS:
                    if pat.search(test_text):
                        dprint(f"PAGER: Found prompt pattern in line: '{test_text}'")
                        return True

        # Also check the rolling tail for patterns that might span multiple lines
        tail = self._recent_tail.strip()
        if tail:
            # Fast check for common patterns
            tail_lower = tail.lower()
            if (("abort" in tail_lower and "continue" in tail_lower) or
                ("press" in tail_lower and "continue" in tail_lower) or
                ("more" in tail_lower) or
                ("--more--" in tail_lower)):

                # Now use regex for precise matching
                for pat in PROMPT_PATTERNS:
                    if pat.search(tail):
                        dprint(f"PAGER: Found prompt pattern in tail: '{tail[-100:]}'")
                        return True

        return False

    # ----- Handshake queue helpers -----
    def queue_after_connect(self, line: str):
        with self._pending_lock:
            self._pending_after_connect.append(line)

    def _flush_after_connect(self):
        with self._pending_lock:
            lines = self._pending_after_connect[:]
            self._pending_after_connect.clear()
        if lines:
            self.on_line(f"[SEND] Flushing {len(lines)} queued line(s) after connect ...")
            for ln in lines:
                self.send_text(ln)

    def _incoming_is_command(self, raw: bytes) -> bool:
        # For frames we receive, the peer sets C=1 in DEST SSID for a command.
        return len(raw) >= 7 and (raw[6] & 0x80) != 0

    # ----- Public ops -----
    def call(self, dest: str):
        self.dest = dest.upper()
        self.vs = 0
        self.vr = 0
        self.state = "AWAIT_UA"
        self._ua_event.clear()
        self._dm_fallback_tried = False
        # Clear any old pending
        with self._pending_lock:
            self._pending_after_connect.clear()

        attempts = max(1, int(getattr(self, "retries", 3)))
        for i in range(1, attempts + 1):
            # probe v2.2 first, then fallback attempts use SABM
            if i == 1:
                self._send_sabme(self.dest)
                probe = "SABME"
            else:
                self._send_sabm(self.dest)
                probe = "SABM"
            self.on_line(f"[LINK] Calling {self.dest}" +
                         (f" via {','.join(self.digis)}" if self.digis else "") +
                         f" (attempt {i}/{attempts}, {probe}) ...")
            t0 = time.time()
            # wait for UA (or implicit I-frame banner) with latch
            while time.time() - t0 < self.retry_wait:
                if self.state == "CONNECTED" or self._ua_event.is_set():
                    return
                time.sleep(0.05)

        # no UA
        self.on_line("[LINK] No response. Giving up.")
        self.state = "DISCONNECTED"
        self.dest = None

    def disconnect(self):
        if self.state == "CONNECTED":
            self._send_disc()
        self.state = "DISCONNECTED"
        self.dest = None
        self.appbuf = ""
        with self._pending_lock:
            self._pending_after_connect.clear()
        self.on_line(f"[LINK] Disconnected.")

    def send_text(self, line: str):
        wire = (line + self.tx_newline).encode("utf-8")
        if self.local_echo:
            self.on_line("> " + line)
        self._send_i(wire)

    def send_unproto(self, dest: str, message: str, digis=None):
        """Send unproto message with digipeater support"""
        wire = message.encode("utf-8", errors="replace")
        self._send_ui(dest, wire, digis=digis or [])
        via = f" via {','.join(digis)}" if digis else ""
        self.on_line(f"[UNPROTO] {dest}{via} :: {message}")

    # ----- Keepalive -----
    def _ka_loop(self):
        # We originate a periodic POLL (RR cmd with P=1) only when connected.
        # Reduce frequency during paging to avoid interfering
        while self._ka_alive:
            if self.state == "CONNECTED":
                # Don't send keepalives during paging interactions
                if not getattr(self, "more_prompt_pending", False):
                    dprint("Keepalive: Sending RR poll")
                    self._send_rr(is_command=True, pf=1)
                else:
                    dprint("Keepalive: Skipping due to pending pager prompt")
            time.sleep(120)  # Increased from 60 to 120 seconds

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

                frame = bytes(buf[start+1:end])
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
        """Check if text contains a pager prompt and update state"""
        # Update rolling tail first
        self._update_recent_tail(text)

        # Check for pager prompts
        if self._detect_pager_prompt(text):
            self.more_prompt_pending = True
            dprint(f"PAGER: Detected prompt in: '{text.strip()}'")

        # Also check for disconnect indicators that might be false positives
        text_lower = text.lower().strip()
        if any(word in text_lower for word in ['disconnect', 'goodbye', 'bye', '73']):
            dprint(f"PAGER: Potential disconnect text: '{text.strip()}'")
        # Do NOT clear here on non-empty text; we clear only after we act on it.

    # ----- AX.25 handlers -----
    def _handle_ax25(self, raw: bytes):
        dprint("RX", raw.hex())
        dest, src, i = decode_addrs(raw)
        if i == 0 or i >= len(raw):
            return
        ctrl = raw[i]
        base = ctrl & 0xEF  # clear P/F for type tests

        # Debug frame info
        if DEBUG:
            frame_type = "Unknown"
            if (ctrl & 0x01) == 0:
                frame_type = f"I-frame ns={(ctrl >> 1) & 0x07} nr={(ctrl >> 5) & 0x07}"
            elif base == CTRL_UA:
                frame_type = "UA"
            elif base == CTRL_DM:
                frame_type = "DM"
            elif base == CTRL_DISC:
                frame_type = "DISC"
            elif base == CTRL_UI:
                frame_type = "UI"
            elif (ctrl & 0x0F) in (S_RR, S_RNR, S_REJ):
                frame_type = f"S-frame {ctrl & 0x0F:02x}"
            dprint(f"Frame: {src}->{dest} {frame_type} state={self.state}")

        # I-frame
        if (ctrl & 0x01) == 0:
            ns = (ctrl >> 1) & 0x07
            pf_in = 1 if (ctrl & 0x10) else 0
            if i + 1 >= len(raw):
                return
            info = raw[i+2:]

            # If banner arrives immediately after SABM/UA, latch the link
            if self.state == "AWAIT_UA":
                self._ua_event.set()
                self.state = "CONNECTED"
                if callable(self.on_connected_ui):
                    self.on_connected_ui()
                self.on_line(f"[LINK] CONNECTED to {self.dest} (implicit)")
                # NOTE: flush-after-connect occurs after we finish printing banner text
                # (we'll let the app print first lines, then user can type)

            if ns == self.vr:
                # Accept in-order I-frame, advance vr, ACK with RR (mirror P/F).
                self.vr = (self.vr + 1) & 7
                self._send_rr(is_command=False, pf=pf_in)   # respond (F mirrors P)

                # text handling
                chunk = info.decode("utf-8", errors="replace")
                chunk = chunk.replace("\r\n", "\n").replace("\r", "\n")
                self.appbuf += chunk

                while "\n" in self.appbuf:
                    line, self.appbuf = self.appbuf.split("\n", 1)
                    line = line.rstrip()
                    if callable(self.on_rx_line):
                        self.on_rx_line(line)
                    else:
                        self.on_line(line)
                    self._check_more_prompt(line)

                # If burst ended (P/F=1) and we still have a partial:
                if pf_in and self.appbuf:
                    peek = self.appbuf.rstrip()
                    # Always display partial content at end of burst
                    if peek:
                        if callable(self.on_rx_line):
                            self.on_rx_line(peek)
                        else:
                            self.on_line(peek)
                        self._check_more_prompt(peek)
                        self.appbuf = ""
            else:
                # Out-of-sequence: ACK current vr without moving it.
                self._send_rr(is_command=False, pf=0)
            return

        # UI frames (monitor mode)
        if base == CTRL_UI:
            if not getattr(self, "unproto_mode", False):
                return
            if i + 1 >= len(raw):
                return
            pid = raw[i+1]
            info = raw[i+2:]
            text = info.decode("utf-8", errors="replace")
            text = text.replace("\r\n", "\n").replace("\r", "\n").rstrip()
            msg = f"[RX UI] {src} > {dest} :: {text}"
            if callable(self.on_rx_line):
                self.on_rx_line(msg)
            else:
                self.on_line(msg)
            return

        # --- U-frames ---
        if base == CTRL_UA:
            self._ua_event.set()
            if self.state == "AWAIT_UA":
                self.state = "CONNECTED"
                if callable(self.on_connected_ui):
                    self.on_connected_ui()
                self.on_line(f"[LINK] CONNECTED to {self.dest}")
                self._flush_after_connect()
            return

        if base == CTRL_DM:
            # DM during handshake -> fallback to SABM once
            if self.state == "AWAIT_UA" and self.dest and not self._dm_fallback_tried:
                self.on_line("[LINK] Peer sent DM; retrying with SABM (v2.0)...")
                self._dm_fallback_tried = True
                self._send_sabm(self.dest)
                return
            self.on_line("[LINK] Disconnected mode (DM) from peer).")
            self.state = "DISCONNECTED"
            self.dest = None
            self.appbuf = ""
            return

        if base == CTRL_FRMR:
            self.on_line("[LINK] FRMR (frame reject) from peer.")
            # If we were probing with SABME, fall back to SABM (v2.0)
            if self.state == "AWAIT_UA" and self.dest:
                self._send_sabm(self.dest)
            return

        if base == CTRL_DISC:
            pf_in = 1 if (ctrl & 0x10) else 0
            # Only respond to DISC if we're actually connected
            # Some BBS systems send spurious DISC frames during paging
            if self.state == "CONNECTED":
                self._send_ua(final=pf_in or 1)
                self.state = "DISCONNECTED"
                self.dest = None
                self.appbuf = ""
                self.on_line("[LINK] Peer requested DISC - disconnected.")
            else:
                dprint(f"DISC: Ignoring DISC in state {self.state}")
            return

        # --- S-frames (RR/RNR/REJ) ---
        s_code = ctrl & 0x0F
        if s_code in (S_RR, S_RNR, S_REJ):
            pf_in = 1 if (ctrl & 0x10) else 0
            nr = (ctrl >> 5) & 0x07
            dprint(f"S-frame: code={s_code:02x} nr={nr} pf={pf_in}")

            # Update our send sequence based on their ACK
            if s_code == S_RR:
                # They're acknowledging up to nr-1, but don't change our vr
                pass

            if pf_in and self._incoming_is_command(raw):
                # They polled us (Command + P=1) -> answer once with Response + F=1
                dprint("S-frame: Responding to poll")
                self._send_rr(is_command=False, pf=1)
            return

# ---------- UI / CLI ----------
HELP = """\
Commands:
  /c | /connect CALL [via DIGI1,DIGI2]   Connect (AX.25)
  /d | /disconnect                       Disconnect
  /unproto DEST [via DIGI1,DIGI2] [msg]  Send UI frame; no msg -> enter unproto mode
  /upexit                                 Exit unproto mode
  /echo on|off                            Local echo
  /crlf on|off                            Send CRLF instead of CR
  /retries N                              Set connect retries (default 3)
  /debug                                  Toggle debug
  /clear | /cls                           Clear screen
  /status                                 Show link status
  /color rx <name>|prompt <name>          Set RX/prompt color (e.g., brightyellow)
  /h | /help [-v]                         Show help (use -v for verbose)
  /q | /quit | /exit                      Quit
"""

HELP_VERBOSE = """\
==============================================================================
                          SIMPLE PACKET TERMINAL
                         Comprehensive Command Guide
==============================================================================

CONNECTION COMMANDS:
  /c CALL                    Connect to CALL (e.g., /c N0CALL)
  /connect CALL              Same as /c
  /c CALL via DIGI1,DIGI2    Connect through digipeaters
  /d                         Disconnect from current station
  /disconnect                Same as /d

UNPROTO (UI) COMMANDS:
  /unproto DEST MESSAGE      Send single UI frame to DEST
  /unproto DEST via DIGI MESSAGE  Send UI frame through digipeaters
  /unproto DEST              Enter persistent unproto mode to DEST
  /unproto DEST via DIGI     Enter persistent mode through digipeaters
  /unproto off               Exit persistent unproto mode
  /upexit                    Same as /unproto off

CONFIGURATION:
  /echo on|off               Enable/disable local echo of sent text
  /crlf on|off               Send CR+LF (on) or just CR (off) line endings
  /retries N                 Set connection retry attempts (default: 3)
  /color rx <name>           Set RX (payload) color; 'none' to disable
  /color prompt <name>       Set prompt color; 'none' to disable
  /debug                     Toggle debug output (shows frame details)

UTILITY:
  /clear                     Clear screen and show header
  /cls                       Same as /clear
  /status                    Show detailed connection and configuration status
  /h                         Show basic help
  /help                      Same as /h
  /help -v                   Show this detailed help
  /q                         Quit the program
  /quit                      Same as /q
  /exit                      Same as /q

USAGE NOTES:
  • When connected, regular text is sent as I-frames to the remote station
  • Empty lines during BBS paging will continue to next page
  • Type 'A' during BBS paging to abort/stop
  • Slash commands starting with unknown options are forwarded to BBS when connected
  • Commands are case-insensitive
  • Use Ctrl+C to interrupt operations

EXAMPLES:
  /c KC1ABC                  Connect to KC1ABC
  /c N0CALL via W1AW-1       Connect via digipeater
  /unproto CQ Hello World    Send "Hello World" to CQ
  /unproto APRS via WIDE1-1,WIDE2-1  Enter APRS mode via path
  /echo on                   Enable local echo
  /status                    Check current settings

==============================================================================
"""

BANNER = """\
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Simple Packet Terminal                               │
│                   Free and Open Source, Without Warranty                    │
│                                 KC3SMW                                      │
└─────────────────────────────────────────────────────────────────────────────┘
"""

def default_on_connected_ui(mycall: str, host: str, port: int):
    """Called when we get a successful connection - clear screen and show connected banner"""
    clear_screen()
    print(BANNER)
    print(f"┌─ KISS Connection: {host}:{port}    ─ MYCALL: {mycall} ─ CONNECTED ─┐")
    print("│                                                                     │")
    print("└─────────────────────────────────────────────────────────────────────┘\n")

def run(mycall: str, target: Optional[str], host: str, port: int):
    # Show startup banner immediately at the very beginning
    print(BANNER)
    print(f"KISS Connection: {host}:{port}  ─   MYCALL: {mycall}")
    print("Type /help for commands, /help -v for detailed help")
    print("───────────────────────────────────────────────────\n")

    link = KissLink(host, port, mycall)

    # --- header printer used at start & on UA & by /clear ---
    def print_header():
        print(BANNER)
        print(f"┌─ KISS Connection: {host}:{port} ─ MYCALL: {mycall} ─┐")
        print("│  Type /help for commands, /help -v for detailed help │")
        print("└───────────────────────────────────────────────────────┘\n")

    def ui_clear_and_header():
        clear_screen()
        print_header()

    # --- dynamic prompt builder with color ---
    def prompt() -> str:
        if link.state == "CONNECTED" and link.dest:
            core = f"[{mycall.upper()} @ {link.dest}] >> "
        else:
            core = f"[{mycall.upper()}] >> "
        return colorize_prompt(core)

    # --- incoming lines: overwrite current input line, then redraw prompt ---
    logfile = open(f"session-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.log", "w", buffering=1)

    def emit(s: str):
        # system/link/unproto notices
        try:
            logfile.write(s + "\n")
        except Exception:
            pass
        with link.ui_lock:
            if _supports_ansi():
                sys.stdout.write("\r\033[2K" + s + "\n")
                sys.stdout.write("\033[2K" + prompt())
            else:
                sys.stdout.write("\r" + s + "\n" + prompt())
            sys.stdout.flush()

    def emit_rx(s: str):
        # payload lines (I-frame text and RX UI monitor)
        try:
            logfile.write(s + "\n")
        except Exception:
            pass
        with link.ui_lock:
            if _supports_ansi():
                sys.stdout.write("\r\033[2K" + colorize_rx(s) + "\n")
                sys.stdout.write("\033[2K" + prompt())
            else:
                sys.stdout.write("\r" + s + "\n" + prompt())
            sys.stdout.flush()

    link.on_line = emit
    link.on_rx_line = emit_rx     # NEW: hook RX payloads to colored emitter
    link.on_connected_ui = lambda: default_on_connected_ui(mycall, host, port)

    # Connect to KISS after banner is shown
    try:
        link.connect()
    except Exception as e:
        print(f"[ERROR] Failed to connect to KISS: {e}")
        return

    # readline history (best-effort)
    if sys.stdin.isatty():
        try:
            import readline  # type: ignore
            histfile = os.path.expanduser("~/.spt_history")
            try:
                readline.read_history_file(histfile)
            except FileNotFoundError:
                pass
            atexit.register(lambda: readline.write_history_file(histfile))
        except Exception:
            pass

    # Optional tip if a target was provided on CLI
    if target:
        print(f"Tip: /c {target}")

    while True:
        try:
            # display prompt and read
            sys.stdout.write(prompt()); sys.stdout.flush()
            line = input("")
        except EOFError:
            break
        except KeyboardInterrupt:
            emit("^C"); break

        # normalize
        line = line.rstrip("\n")
        cmd  = line.strip()
        low  = cmd.lower()
        toks = low.split()
        ftok = toks[0] if toks else ""

        # UNPROTO persistent mode: plain lines go as UI frames
        if cmd and not cmd.startswith("/") and link.unproto_mode and link.unproto_dest:
            link.send_unproto(link.unproto_dest, cmd, link.unproto_digis)
            continue

        # If we're handshaking (AWAIT_UA): queue any *plain* text until UA
        if cmd and not cmd.startswith("/") and link.state != "CONNECTED":
            link.queue_after_connect(cmd)
            print(f"[QUEUED] Will send after link to {link.dest or '(pending)'} comes up.")
            continue

        # Empty line: pager continue or normal behavior
        if not cmd:
            if getattr(link, "more_prompt_pending", False):
                dprint("PAGER: Sending CR to continue")
                link.send_text("")  # Send just CR
                link.more_prompt_pending = False
            continue

        # Pager abort - handle both 'a' and 'A'
        if getattr(link, "more_prompt_pending", False) and low in ("a", "abort"):
            dprint("PAGER: Sending abort")
            link.send_text("A")
            link.more_prompt_pending = False
            continue

        # quit / exit
        if ftok in ("/q", "/quit", "/exit"):
            link.disconnect()
            break

        # help
        if ftok in ("/h", "/help"):
            if len(toks) >= 2 and toks[1] == "-v":
                print(HELP_VERBOSE)
            else:
                print(HELP)
            continue

        # disconnect
        if ftok in ("/d", "/disconnect"):
            link.disconnect()
            # redraw prompt immediately
            sys.stdout.write("\r\033[2K" + prompt()); sys.stdout.flush()
            continue

        # connect
        if ftok in ("/c", "/connect"):
            parts = cmd.split()
            dest = parts[1] if len(parts) > 1 else (target or "")
            digis: List[str] = []
            # support "via" 2 or 3 words after dest
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

        # status
        if ftok == "/status":
            via = f" via {','.join(link.digis)}" if link.digis else ""
            unproto_via = f" via {','.join(link.unproto_digis)}" if link.unproto_digis else ""
            print(f"[STATUS] state={link.state} dest={link.dest or '(none)'} vs={link.vs} vr={link.vr}")
            print(f"         digis={via or '[]'} echo={'on' if link.local_echo else 'off'} crlf={'on' if link.tx_newline=='\r\n' else 'off'}")
            print(f"         retries={link.retries} unproto={'on' if link.unproto_mode else 'off'} to={link.unproto_dest or '(none)'}{unproto_via}")
            print(f"         pager_pending={link.more_prompt_pending}")
            continue

        # echo
        if ftok == "/echo" and len(toks) >= 2:
            link.local_echo = toks[1] == "on"
            print(f"[ECHO] {'on' if link.local_echo else 'off'}")
            continue

        # crlf
        if ftok == "/crlf" and len(toks) >= 2:
            link.tx_newline = "\r\n" if toks[1] == "on" else "\r"
            print(f"[CRLF] {'on' if link.tx_newline=='\r\n' else 'off (CR only)'}")
            continue

        # retries
        if ftok == "/retries" and len(toks) >= 2:
            try:
                link.retries = max(1, int(toks[1]))
                print(f"[RETRIES] {link.retries}")
            except ValueError:
                print("[RETRIES] must be an integer >= 1")
            continue

        # debug
        if ftok == "/debug":
            global DEBUG
            DEBUG = not DEBUG
            print(f"[DEBUG] {'on' if DEBUG else 'off'}")
            continue

        # color
        if ftok == "/color":
            COLORS = {
                "black":"\033[30m","red":"\033[31m","green":"\033[32m","yellow":"\033[33m",
                "blue":"\033[34m","magenta":"\033[35m","cyan":"\033[36m","white":"\033[37m",
                "brightblack":"\033[90m","brightred":"\033[91m","brightgreen":"\033[92m",
                "brightyellow":"\033[93m","brightblue":"\033[94m","brightmagenta":"\033[95m",
                "brightcyan":"\033[96m","brightwhite":"\033[97m",
                "none":""  # disables coloring for that target
            }
            if len(toks) >= 3 and toks[1] in ("rx","prompt"):
                target_name, color_name = toks[1], toks[2]
                if color_name in COLORS:
                    global RX_COLOR, PROMPT_COLOR
                    if target_name == "rx":
                        RX_COLOR = COLORS[color_name]
                    else:
                        PROMPT_COLOR = COLORS[color_name]
                    print(f"[COLOR] {target_name} set to {color_name}")
                else:
                    print("[COLOR] Unknown color. Try: green, yellow, magenta, brightcyan, none …")
            else:
                print("Usage: /color rx <name> | /color prompt <name>")
            continue

        # UNPROTO with improved digipeater support
        if ftok == "/unproto":
            # forms:
            #   /unproto DEST [via DIGI1,DIGI2] message...
            #   /unproto DEST [via DIGI1,DIGI2]
            #   /unproto off|stop|end|exit
            if len(toks) >= 2 and toks[1] in ("off","stop","end","exit"):
                link.unproto_mode = False
                link.unproto_dest = None
                link.unproto_digis = []
                print("[UNPROTO] off")
                continue

            parts = cmd.split()
            if len(parts) >= 2:
                dest = parts[1].upper()
                digis = []
                msg_start = 2
                if len(parts) >= 4 and parts[2].lower() == "via":
                    # Parse digipeater list
                    digis = [d.strip().upper() for d in parts[3].split(",") if d.strip()]
                    msg_start = 4
                if msg_start < len(parts):
                    # one-shot with message
                    msg = " ".join(parts[msg_start:])
                    link.send_unproto(dest, msg, digis)
                else:
                    # enter persistent mode
                    link.unproto_mode = True
                    link.unproto_dest = dest
                    link.unproto_digis = digis
                    via = f" via {','.join(digis)}" if digis else ""
                    print(f"[UNPROTO] persistent: {link.unproto_dest}{via}")
                continue

            print("Usage: /unproto DEST [via DIGI1,DIGI2] [message...]  |  /unproto off")
            continue

        # Exit unproto mode
        if ftok == "/upexit":
            if link.unproto_mode:
                link.unproto_mode = False
                link.unproto_dest = None
                link.unproto_digis = []
                print("[UNPROTO] exited persistent mode")
            else:
                print("[UNPROTO] not in persistent mode")
            continue

        # unknown slash-commands: forward when connected (BBS-friendly)
        if cmd.startswith("/") and link.state == "CONNECTED":
            link.send_text(cmd)
            continue

        # plain text in connected mode
        if link.state == "CONNECTED":
            link.send_text(cmd)
            continue

        print("Unknown command. /h for help.")

def main():
    # Clear screen immediately when program starts - before any other output
    clear_screen()

    # CLI forms:
    #   SPT_0_9a.py MYCALL
    #   SPT_0_9a.py MYCALL TARGET
    #   SPT_0_9a.py MYCALL TARGET HOST PORT
    #   SPT_0_9a.py MYCALL TARGET HOST:PORT
    argv = sys.argv[:]
    if len(argv) < 2:
        print("Usage: SPT_0_9a.py MYCALL [TARGET] [HOST] [PORT]  |  SPT_0_9a.py MYCALL TARGET HOST:PORT")
        sys.exit(1)
    mycall = argv[1].upper()
    target = None
    host, port = KISS_HOST_DEFAULT, KISS_PORT_DEFAULT

    if len(argv) >= 3:
        target = argv[2]
    if len(argv) >= 4:
        if ":" in argv[3]:
            host, p = argv[3].split(":", 1)
            port = int(p)
        else:
            host = argv[3]
            if len(argv) >= 5:
                port = int(argv[4])

    try:
        run(mycall, target, host, port)
    finally:
        pass

if __name__ == "__main__":
    main()
