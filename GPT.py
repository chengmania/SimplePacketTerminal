#!/usr/bin/env python3
"""
GPT — GUI-Packet Terminal (Tkinter + ttkbootstrap)

A desktop GUI for your Simple Packet Terminal:
- AX.25 Connected mode + UNPROTO (UI) frames
- Handshake queue: plain lines typed while AWAIT_UA are sent after UA
- Pager-aware: shows Continue/Abort when "<A>bort, <CR> Continue..>" appears
- Arrow-key history, local echo toggle, CR/LF toggle, debug toggle
- Clean, modern layout using ttkbootstrap

Author: Chengmania (KC3SMW) + ChatGPT
"""

import os, sys, socket, threading, time, datetime, re, queue
import tkinter as tk
from tkinter import scrolledtext, messagebox
try:
    import ttkbootstrap as tb
    from ttkbootstrap.toast import ToastNotification
except Exception as e:
    print("This app uses ttkbootstrap for styling. Install with:\n  pip install ttkbootstrap")
    raise

# =========================
# ==== Radio Core (AX.25 / KISS) ====
# (Adapted from your SPT2.py with minimal changes)
# =========================

PROMPT_PATTERNS = [
    re.compile(r"<\s*A\s*>?bort,\s*<\s*CR\s*>\s*Continue\.\.?>", re.I),
    re.compile(r"press\s*<\s*cr\s*>\s*to\s*continue", re.I),
]

KISS_HOST_DEFAULT = "127.0.0.1"
KISS_PORT_DEFAULT = 8001
DEBUG = False

FEND  = 0xC0
FESC  = 0xDB
TFEND = 0xDC
TFESC = 0xDD
KISS_DATA = 0x00

CTRL_SABM = 0x2F
CTRL_UA   = 0x63
CTRL_DISC = 0x43
CTRL_DM   = 0x0F
CTRL_FRMR = 0x87
CTRL_UI   = 0x03

S_RR  = 0x01
S_RNR = 0x05
S_REJ = 0x09

PID_NO_L3 = 0xF0

def dprint(*a):
    if DEBUG: print("[DBG]", *a)

def parse_call(call: str):
    call = call.upper().strip()
    if "-" in call:
        base, ssid = call.split("-", 1)
        ssid = int(ssid or "0")
    else:
        base, ssid = call, 0
    return base, ssid

def ax25_addr_bytes(call: str, last: bool, command: bool):
    base, ssid = parse_call(call)
    base = (base + "      ")[:6]
    b = bytearray(7)
    for i, ch in enumerate(base):
        b[i] = (ord(ch) << 1) & 0xFE
    ssid_byte = 0x60 | ((ssid & 0x0F) << 1)
    if command: ssid_byte |= 0x80
    if last:    ssid_byte |= 0x01
    b[6] = ssid_byte
    return bytes(b)

def build_ax25_header(dest: str, src: str, digis=None, cmd=True):
    digis = digis or []
    parts = [
        ax25_addr_bytes(dest, last=False, command=cmd),
        ax25_addr_bytes(src,  last=(len(digis) == 0), command=not cmd),
    ]
    for i, d in enumerate(digis):
        parts.append(ax25_addr_bytes(d, last=(i == len(digis) - 1), command=False))
    return b"".join(parts)

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

def kiss_escape(payload: bytes) -> bytes:
    payload = payload.replace(bytes([FESC]), bytes([FESC, TFESC]))
    payload = payload.replace(bytes([FEND]), bytes([FESC, TFEND]))
    return payload

def kiss_unescape(payload: bytes) -> bytes:
    out = bytearray(); i = 0
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

class KissLink:
    """Minimal LAPB link over KISS TCP. UI hooks are set by the GUI."""
    def __init__(self, host, port, mycall):
        self.host, self.port = host, port
        self.mycall = mycall.upper()
        self.sock = None
        self.alive = False
        self.rx_thread = None
        self.on_line = print             # callback(str)
        self.on_connected_ui = None      # callback()
        # AX.25 state
        self.state = "DISCONNECTED"
        self.dest = None
        self.vs = 0
        self.vr = 0
        self.appbuf = ""
        self.digis = []
        # QoL
        self.local_echo = False
        self.tx_newline = "\r"
        # Keepalive
        self._ka_alive = False
        self._ka_thread = None
        self.more_prompt_pending = False
        self.ui_lock = threading.Lock()
        # Unproto state
        self.unproto_mode = False
        self.unproto_dest = None
        self.unproto_digis = []
        # Pending lines until UA
        self._pending_lock = threading.Lock()
        self._pending_after_connect = []

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
            if self.sock: self.sock.close()
        except: pass
        self.sock = None

    # ----- AX.25 TX helpers -----
    def _send_ax25(self, raw: bytes, port=0):
        if not self.sock: return
        frame = kiss_wrap_data(port, raw)
        self.sock.sendall(frame)
        dprint("TX", raw.hex())

    def _send_sabm(self, dest):
        hdr = build_ax25_header(dest, self.mycall, self.digis)
        ctrl = CTRL_SABM | 0x10
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
        if pf: ctrl |= 0x10
        self._send_ax25(hdr + bytes([ctrl]))

    def _send_i(self, text: bytes):
        if not self.dest or self.state != "CONNECTED": return
        hdr = build_ax25_header(self.dest, self.mycall, self.digis)
        ctrl = ((self.vs & 0x07) << 1) | ((self.vr & 0x07) << 5)
        self.vs = (self.vs + 1) & 7
        pkt = hdr + bytes([ctrl, PID_NO_L3]) + text
        self._send_ax25(pkt)

    def _send_ui(self, dest: str, message: bytes, digis=None):
        digis = digis or []
        hdr = build_ax25_header(dest.upper(), self.mycall, digis)
        ctrl = CTRL_UI
        pkt = hdr + bytes([ctrl, PID_NO_L3]) + message
        self._send_ax25(pkt)

    # ----- Handshake queue -----
    def queue_after_connect(self, line: str):
        with self._pending_lock:
            self._pending_after_connect.append(line)

    def _flush_after_connect(self):
        with self._pending_lock:
            lines = self._pending_after_connect[:]
            self._pending_after_connect.clear()
        if lines:
            self.on_line(f"[SEND] Flushing {len(lines)} queued line(s) after connect …")
            for ln in lines:
                self.send_text(ln)

    # ----- Public ops -----
    def call(self, dest):
        self.dest = dest.upper()
        self.vs = 0; self.vr = 0
        self.state = "AWAIT_UA"
        with self._pending_lock:
            self._pending_after_connect.clear()
        self._send_sabm(self.dest)
        via = f" via {','.join(self.digis)}" if self.digis else ""
        self.on_line(f"[LINK] Calling {self.dest}{via} …")

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
        wire = message.encode("utf-8", errors="replace")
        self._send_ui(dest, wire, digis=digis or [])
        via = f" via {','.join(digis)}" if digis else ""
        self.on_line(f"[UNPROTO] {dest}{via} :: {message}")

    # ----- Keepalive -----
    def _ka_loop(self):
        while self._ka_alive:
            if self.state == "CONNECTED":
                self._send_rr(pf=1)
            time.sleep(60)

    # ----- RX path -----
    def _rx_loop(self):
        buf = bytearray()
        while self.alive:
            try:    chunk = self.sock.recv(4096)
            except socket.timeout: continue
            except Exception: break
            if not chunk: break
            buf.extend(chunk)

            while True:
                try: start = buf.index(FEND)
                except ValueError:
                    buf.clear(); break
                try: end = buf.index(FEND, start+1)
                except ValueError:
                    if start > 0: del buf[:start]
                    break

                frame = bytes(buf[start+1:end])
                del buf[:end+1]
                if not frame: continue
                port_type = frame[0]
                if (port_type & 0x0F) != KISS_DATA: continue
                raw = kiss_unescape(frame[1:])
                if not raw: continue
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
        if not self.dest: return
        hdr = build_ax25_header(self.dest, self.mycall, self.digis, cmd=False)
        ctrl = CTRL_UA | (0x10 if final else 0)
        self._send_ax25(hdr + bytes([ctrl]))

    def _handle_ax25(self, raw: bytes):
        dprint("RX", raw.hex())
        dest, src, i = decode_addrs(raw)
        if i == 0 or i >= len(raw): return
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

        base = ctrl & 0xEF

        # U-frames
        if base == CTRL_UA:
            if self.state == "AWAIT_UA":
                self.state = "CONNECTED"
                if callable(self.on_connected_ui):
                    self.on_connected_ui()
                self.on_line(f"[LINK] CONNECTED to {self.dest}\n")
                self._flush_after_connect()
            return
        if base == CTRL_DM:
            self.on_line("[LINK] Disconnected mode (DM) from peer).")
            self.state = "DISCONNECTED"; self.dest = None; self.appbuf = ""
            return
        if base == CTRL_FRMR:
            self.on_line("[LINK] FRMR (frame reject) from peer.")
            return
        if base == CTRL_DISC:
            pf_in = 1 if (ctrl & 0x10) else 0
            self._send_ua(final=pf_in or 1)
            self.state = "DISCONNECTED"; self.dest = None; self.appbuf = ""
            self.on_line("[LINK] Peer requested DISC.")
            return

        # S-frames
        s_code = ctrl & 0x0F
        if s_code in (S_RR, S_RNR, S_REJ):
            return

# =========================
# ==== GUI Layer (Tkinter + ttkbootstrap) ====
# =========================

APP_TITLE = "GPT — GUI-Packet Terminal"
BANNER = (
    "SPT — Simple Packet Terminal\n"
    "An open-source KISS/AX.25 terminal for amateur radio.\n"
    "Created by Chengmania (KC3SMW).\n"
    "\n"
    "• Works with Direwolf (KISS TCP)\n"
    "• Clean, pager-friendly display\n"
    "• Connected mode (/connect) and UNPROTO (UI) frames\n"
)

class GPTApp:
    def __init__(self, root: tb.Window):
        self.root = root
        self.style = tb.Style(theme="flatly")  # pick a nice theme; others: cosmo, cyborg, litera, darkly …
        root.title(APP_TITLE)
        root.geometry("1100x720")

        # inbound lines from radio thread -> GUI
        self.in_q: "queue.Queue[str]" = queue.Queue()

        # history
        self.history: list[str] = []
        self.hist_idx: int = -1

        # session log
        ts = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        self.logf = open(f"session-{ts}.log", "w", buffering=1)

        # link (created on Connect)
        self.link: KissLink | None = None

        # ====== Layout ======
        self._build_toolbar()
        self._build_console()
        self._build_pager()
        self._autosize_initial()
        #self._build_statusbar()   # build the bottom status bar


        # periodic GUI updater
        self._tick()

        # shortkeys
        self.root.bind("<Control-l>", lambda e: self.clear_console())
        self.root.bind("<Escape>", lambda e: self.entry.focus_set())
        self.entry.bind("<Return>", self._on_enter)
        self.entry.bind("<Up>", self._on_history_up)
        self.entry.bind("<Down>", self._on_history_down)

        # banner at start
        self._emit(BANNER.strip())

    # ---------- UI sections ----------
    def _autosize_initial(self, width_cap=1400, height_cap=900, pad_h=40, pad_w=40):
        """
        Size the window so all top sections are visible without manual resize,
        capped to screen size (so we don't exceed small displays).
        """
        self.root.update_idletasks()  # ensure widgets know their req sizes

        # compute desired width/height from packed children
        # we rely on our three main stacks: toolbar, console_wrap, pager (hidden), etc.
        total_w = 0
        total_h = 0
        for child in self.root.winfo_children():
            if not child.winfo_ismapped():
                continue
            total_w = max(total_w, child.winfo_reqwidth())
            total_h += child.winfo_reqheight()

        # add padding/margins
        total_w += pad_w
        total_h += pad_h

        # respect screen size; add a gentle cap
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        w = min(total_w, sw - 60, width_cap)
        h = min(total_h, sh - 80, height_cap)

        # apply and set a sensible minimum so it doesn't collapse
        self.root.geometry(f"{int(w)}x{int(h)}")
        self.root.minsize(int(min(w, 900)), int(min(h, 420)))

    def _build_toolbar(self):
        top = tb.Frame(self.root, padding=10)
        top.pack(fill="x")

        # LEFT column only (Connection over Settings)
        left = tb.Frame(top)
        left.pack(fill="x", expand=True)

        # ---- Connection ----
        cg = tb.Labelframe(left, text="Connection", padding=(8,6))
        cg.pack(fill="x")
        self.var_mycall = tk.StringVar(value="KC3SMW")
        self.var_dest   = tk.StringVar(value="")
        self.var_digis  = tk.StringVar(value="")
        self.var_host   = tk.StringVar(value=KISS_HOST_DEFAULT)
        self.var_port   = tk.IntVar(value=KISS_PORT_DEFAULT)

        tb.Entry(cg, width=10, textvariable=self.var_mycall).grid(row=0, column=0, padx=4, pady=2)
        tb.Entry(cg, width=12, textvariable=self.var_dest).grid(  row=0, column=1, padx=4, pady=2)
        tb.Entry(cg, width=18, textvariable=self.var_digis).grid( row=0, column=2, padx=4, pady=2)
        tb.Entry(cg, width=14, textvariable=self.var_host).grid(  row=0, column=3, padx=4, pady=2)
        tb.Entry(cg, width=6,  textvariable=self.var_port).grid(  row=0, column=4, padx=4, pady=2)

        tb.Label(cg, text="MYCALL").grid(row=1, column=0)
        tb.Label(cg, text="DEST").grid(  row=1, column=1)
        tb.Label(cg, text="Digis (comma)").grid(row=1, column=2)
        tb.Label(cg, text="Host").grid(  row=1, column=3)
        tb.Label(cg, text="Port").grid(  row=1, column=4)

        self.btn_connect = tb.Button(cg, text="Connect", bootstyle="success-outline", command=self.connect)
        self.btn_disc    = tb.Button(cg, text="Disconnect", bootstyle="danger-outline", command=self.disconnect, state="disabled")
        self.btn_connect.grid(row=0, column=5, padx=(8,4))
        self.btn_disc.grid(   row=0, column=6, padx=(4,8))

        # ---- Settings (stacked under Connection) ----
        tg = tb.Labelframe(left, text="Settings", padding=(8,6))
        tg.pack(fill="x", pady=(8,0))

        self.var_echo = tk.BooleanVar(value=True)
        self.var_crlf = tk.BooleanVar(value=False)
        self.var_debug = tk.BooleanVar(value=False)
        self.var_unproto = tk.BooleanVar(value=False)
        self.var_unproto_dest = tk.StringVar(value="")
        self.var_unproto_digis = tk.StringVar(value="")

        tb.Checkbutton(tg, text="Echo",  variable=self.var_echo,  command=self._apply_echo).pack(side="left", padx=6)
        tb.Checkbutton(tg, text="CRLF",  variable=self.var_crlf,  command=self._apply_crlf).pack(side="left", padx=6)
        tb.Checkbutton(tg, text="Debug", variable=self.var_debug, command=self._apply_debug).pack(side="left", padx=6)
        tb.Separator(tg, orient="vertical").pack(side="left", fill="y", padx=8, pady=2)
        tb.Checkbutton(tg, text="UNPROTO", variable=self.var_unproto, command=self._toggle_unproto).pack(side="left", padx=(0,6))
        tb.Entry(tg, width=12, textvariable=self.var_unproto_dest).pack(side="left", padx=4)
        tb.Entry(tg, width=18, textvariable=self.var_unproto_digis).pack(side="left", padx=4)
        tb.Label(tg, text="Dest / Digis").pack(side="left", padx=(4,0))



    def _build_console(self):
        # Always-visible console area
        self.console_wrap = tb.Frame(self.root, padding=(10,0,10,6))
        self.console_wrap.pack(fill="both", expand=True)

        # RX text area
        self.console = scrolledtext.ScrolledText(self.console_wrap, wrap="word", height=20)
        self.console.pack(fill="both", expand=True)
        self.console.configure(font=("JetBrains Mono", 11))
        self.console.configure(state="disabled")

        # TX row  ——  [ Entry | Send ]
        tx_row = tb.Frame(self.console_wrap)
        tx_row.pack(fill="x", pady=(8,0))

        self.entry = tb.Entry(tx_row)
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.focus_set()

        self.btn_send = tb.Button(tx_row, text="Send", bootstyle="primary", command=self.send_line)
        self.btn_send.pack(side="left", padx=(8,2))

        # Status row  ——  [Badge]  [MYCALL @ DEST]    |    [Status] [Clear]
        status_row = tb.Frame(self.console_wrap)
        status_row.pack(fill="x", pady=(6,0))

        left = tb.Frame(status_row)
        left.pack(side="left")

        # connection badge
        self.badge_link = tb.Label(left, text="DISCONNECTED", bootstyle="secondary-inverse")
        self.badge_link.pack(side="left", padx=(0,8))

        # live link label (replaces the old 'prompt' label)
        self.lbl_link = tb.Label(left, text="[DISCONNECTED] >>")
        self.lbl_link.pack(side="left", padx=(0,8))

        # keep this so call_dest() can still update the arrow text
        self.lbl_dest = tb.Label(left, text="—")
        self.lbl_dest.pack(side="left", padx=(6,0))

        right = tb.Frame(status_row)
        right.pack(side="right")

        tb.Button(right, text="Status", bootstyle="info-outline", command=self.show_status).pack(side="left", padx=4)
        tb.Button(right, text="Clear",  bootstyle="secondary-outline", command=self.clear_console).pack(side="left", padx=4)



    def _build_pager(self):
        self.pager = tb.Frame(self.root, padding=8)
        self.pager.pack(fill="x")
        self.pager.configure(borderwidth=1)
        self.pager.configure(style="info.TFrame")

        self.pager_label = tb.Label(self.pager, text="Pager prompt detected: Continue or Abort?")
        self.pager_label.pack(side="left", padx=6)

        self.btn_continue = tb.Button(self.pager, text="Continue (Enter)", bootstyle="info", command=self.pager_continue)
        self.btn_abort    = tb.Button(self.pager, text="Abort (A)", bootstyle="danger", command=self.pager_abort)
        self.btn_continue.pack(side="left", padx=4)
        self.btn_abort.pack(side="left", padx=4)

        self.pager.pack_forget()  # hidden by default

    def _build_statusbar(self):
        sb = tb.Frame(self.root, padding=(10,6,10,8))
        sb.pack(fill="x")

        left = tb.Frame(sb)
        left.pack(side="left")
        self.badge_link = tb.Label(left, text="DISCONNECTED", bootstyle="secondary-inverse")
        self.badge_link.pack(side="left", padx=(0,8))
        self.lbl_dest = tb.Label(left, text="—")
        self.lbl_dest.pack(side="left")

        right = tb.Frame(sb)
        right.pack(side="right")
        tb.Button(right, text="Status", bootstyle="info-outline", command=self.show_status).pack(side="left", padx=4)
        tb.Button(right, text="Clear",  bootstyle="secondary-outline", command=self.clear_console).pack(side="left", padx=4)


    # ---------- Connect/Disconnect ----------
    def connect(self):
        if self.link and self.link.alive:
            messagebox.showinfo("Info", "Already connected.")
            return
        mycall = self.var_mycall.get().strip()
        host   = self.var_host.get().strip() or KISS_HOST_DEFAULT
        port   = int(self.var_port.get() or KISS_PORT_DEFAULT)
        dest   = self.var_dest.get().strip()
        digis  = [d.strip().upper() for d in self.var_digis.get().split(",") if d.strip()]

        try:
            self.link = KissLink(host, port, mycall)
            self.link.on_line = self._enqueue_line
            self.link.on_connected_ui = self._on_connected_ui
            self.link.connect()

            self._emit(f"⟨KISS AX.25 Terminal⟩ MYCALL={mycall}  KISS={host}:{port}")
            self.link.digis = digis
            # apply toggles
            self.link.local_echo = self.var_echo.get()
            self.link.tx_newline = "\r\n" if self.var_crlf.get() else "\r"
            self._set_badge("AWAIT", "warning-inverse")
            self._set_prompt(mycall, None)
            self.btn_connect.configure(state="disabled")
            self.btn_disc.configure(state="normal")
            # show tip and optional auto-call
            self._emit(f"⟨KISS AX.25 Terminal⟩ MYCALL={mycall}  KISS={host}:{port}")
            if dest:
                self.call_dest(dest)
        except Exception as e:
            messagebox.showerror("Connect failed", str(e))
            self._set_badge("DISCONNECTED", "secondary-inverse")
            self.btn_connect.configure(state="normal")
            self.btn_disc.configure(state="disabled")

    def call_dest(self, dest: str):
        if not self.link: return
        self.link.call(dest)
        self.lbl_dest.configure(text=f"→ {dest}")

    def disconnect(self):
        if self.link:
            try: self.link.disconnect()
            except Exception: pass
            try: self.link.close()
            except Exception: pass
            self.link = None
        self._set_badge("DISCONNECTED", "secondary-inverse")
        self._set_prompt(None, None)

        self.btn_connect.configure(state="normal")
        self.btn_disc.configure(state="disabled")

    # ---------- Sending ----------
    def send_line(self):
        txt = self.entry.get()
        self.entry.delete(0, "end")
        if not txt and self._pager_shown():
            # Enter on pager -> continue
            self.pager_continue()
            return
        if not self.link:
            self._emit("Not connected.")
            return

        cmd = txt.strip()
        # UNPROTO persistent mode: plain lines -> UI frames
        if cmd and not cmd.startswith("/") and self.link.unproto_mode and self.link.unproto_dest:
            self.link.send_unproto(self.link.unproto_dest, cmd, self.link.unproto_digis)
            self._push_history(txt)
            return

        # Queue plain text during AWAIT_UA
        if cmd and not cmd.startswith("/") and self.link.state != "CONNECTED":
            self.link.queue_after_connect(cmd)
            self._emit(f"[QUEUED] Will send after link to {self.link.dest or '(pending)'} comes up.")
            self._push_history(txt)
            return

        # Pager Abort
        if self._pager_shown() and cmd.lower() == "a":
            self.pager_abort()
            self._push_history(txt)
            return

        # Slash commands
        low = cmd.lower()
        toks = low.split()
        ftok = toks[0] if toks else ""

        if ftok in ("/q","/quit","/exit"):
            self.disconnect(); return
        if ftok in ("/d","/disconnect"):
            self.disconnect(); return
        if ftok in ("/c","/connect"):
            # /c CALL [via DIGI1,DIGI2]
            parts = cmd.split()
            dest = parts[1] if len(parts) > 1 else self.var_dest.get().strip()
            digis = []
            if len(parts) >= 4 and parts[2].lower() == "via":
                digis = [d.strip().upper() for d in parts[3].split(",") if d.strip()]
            if not dest:
                self._emit("Usage: /connect <DEST> [via DIGI1,DIGI2]")
            else:
                if self.link:
                    self.link.digis = digis
                    self.call_dest(dest)
            self._push_history(txt)
            return

        if ftok in ("/clear","/cls"):
            self.clear_console(); self._push_history(txt); return

        if ftok == "/unproto":
            ups = cmd.split()
            if len(ups) >= 2 and ups[1].lower() in ("off","stop","end","exit"):
                if self.link:
                    self.link.unproto_mode = False
                    self.link.unproto_dest = None
                    self.link.unproto_digis = []
                self.var_unproto.set(False)
                self._emit("[UNPROTO] Persistent mode OFF.")
                self._push_history(txt)
                return

            if len(ups) < 2:
                self._emit("Usage: /unproto DEST [via DIGI1,DIGI2] [message...]")
                self._emit("       /unproto off|stop|end|exit")
                self._push_history(txt)
                return

            dest = ups[1].upper()
            digis = []
            msg = ""

            via_idx = None
            for i,t in enumerate(ups):
                if t.lower()=="via":
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
                if self.link: self.link.send_unproto(dest, msg, digis)
            else:
                if self.link:
                    self.link.unproto_mode = True
                    self.link.unproto_dest = dest
                    self.link.unproto_digis = digis
                self.var_unproto.set(True)
                via = f" via {','.join(digis)}" if digis else ""
                self._emit(f"[UNPROTO] Persistent mode ON -> {dest}{via}. Type /upexit to exit.")
            self._push_history(txt); return

        if low in ("/upexit","/upoff","/upstop"):
            if self.link and self.link.unproto_mode:
                self.link.unproto_mode = False
                self.link.unproto_dest = None
                self.link.unproto_digis = []
                self.var_unproto.set(False)
                self._emit("[UNPROTO] Persistent mode OFF.")
            else:
                self._emit("[UNPROTO] Not in unproto mode.")
            self._push_history(txt); return

        if ftok == "/status":
            self.show_status(); self._push_history(txt); return

        if ftok == "/debug":
            self.var_debug.set(not self.var_debug.get())
            self._apply_debug(); self._push_history(txt); return

        if ftok == "/echo":
            if len(toks)==2 and toks[1] in ("on","off"):
                self.var_echo.set(toks[1]=="on"); self._apply_echo()
            else:
                self._emit("Usage: /echo on|off")
            self._push_history(txt); return

        if ftok == "/crlf":
            if len(toks)==2 and toks[1] in ("on","off"):
                self.var_crlf.set(toks[1]=="on"); self._apply_crlf()
            else:
                self._emit("Usage: /crlf on|off")
            self._push_history(txt); return

        if ftok in ("/h","/help"):
            self._emit("Commands: /c|/connect CALL [via DIGI1,DIGI2] | /d|/disconnect | /q|/quit|/exit |")
            self._emit("/clear|/cls | /unproto DEST [via DIGI1,DIGI2] [msg...] | /upexit | /status | /echo on|off | /crlf on|off | /debug")
            self._push_history(txt); return

        # Unknown slash command: forward to peer if connected
        if cmd.startswith("/"):
            if self.link and self.link.state == "CONNECTED" and not self.link.unproto_mode:
                self.link.send_text(cmd)
            else:
                self._emit("command not found; use /help")
            self._push_history(txt); return

        # Plain text -> connected send
        if self.link:
            self.link.send_text(txt)
        self._push_history(txt)

    # ---------- Pager ----------
    def _pager_shown(self) -> bool:
        return self.pager.winfo_ismapped()

    def pager_continue(self):
        if self.link:
            self.link.send_text("")
            self.link.more_prompt_pending = False
        self._hide_pager()

    def pager_abort(self):
        if self.link:
            self.link.send_text("A")
            self.link.more_prompt_pending = False
        self._hide_pager()

    def _maybe_toggle_pager(self):
        if self.link and getattr(self.link, "more_prompt_pending", False):
            if not self._pager_shown():
                self.pager.pack(fill="x")
        else:
            self._hide_pager()

    def _hide_pager(self):
        if self._pager_shown():
            self.pager.pack_forget()

    # ---------- Toggles ----------
    def _apply_echo(self):
        if self.link:
            self.link.local_echo = self.var_echo.get()

    def _apply_crlf(self):
        if self.link:
            self.link.tx_newline = "\r\n" if self.var_crlf.get() else "\r"

    def _apply_debug(self):
        global DEBUG
        DEBUG = self.var_debug.get()
        self._emit(f"[DEBUG] {'ON' if DEBUG else 'OFF'}")

    def _toggle_unproto(self):
        if not self.link:
            self.var_unproto.set(False)
            self._emit("Connect first to use UNPROTO settings.")
            return

        if self.var_unproto.get():
            dest = (self.var_unproto_dest.get() or "").strip().upper()
            digis = [d.strip().upper() for d in self.var_unproto_digis.get().split(",") if d.strip()]
            if not dest:
                self._emit("UNPROTO requires Dest. Fill it, then toggle again.")
                self.var_unproto.set(False); return
            self.link.unproto_mode = True
            self.link.unproto_dest = dest
            self.link.unproto_digis = digis
            via = f" via {','.join(digis)}" if digis else ""
            self._emit(f"[UNPROTO] Persistent mode ON -> {dest}{via}.")
        else:
            self.link.unproto_mode = False
            self.link.unproto_dest = None
            self.link.unproto_digis = []
            self._emit("[UNPROTO] Persistent mode OFF.")

    # ---------- Status, Console ----------
    def show_status(self):
        if not self.link:
            self._emit("[STATUS] not connected"); return
        echo_on = "on" if self.link.local_echo else "off"
        crlf_on = "on" if self.link.tx_newline == "\r\n" else "off"
        up = "on" if self.link.unproto_mode else "off"
        up_to = self.link.unproto_dest or "(none)"
        up_via = ",".join(self.link.unproto_digis) if self.link.unproto_digis else "[]"
        self._emit(f"[STATUS] state={self.link.state} dest={self.link.dest or '(none)'} vs={self.link.vs} vr={self.link.vr} "
                   f"digis={self.link.digis or '[]'} echo={echo_on} crlf={crlf_on} unproto={up} to={up_to} via={up_via}")

    def clear_console(self):
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")
        self._emit("Screen cleared. Type /help for commands.")

    def _emit(self, s: str):
        try: self.logf.write(s + "\n")
        except Exception: pass
        self.console.configure(state="normal")
        self.console.insert("end", s + "\n")
        self.console.configure(state="disabled")
        self.console.see("end")

    # ---------- Thread-safe line ingress ----------
    def _enqueue_line(self, s: str):
        # called from radio thread
        self.in_q.put(s)

    def _on_connected_ui(self):
        # called from radio thread (safe -> queue an action line)
        self.in_q.put("__UI_CLEAR_HEADER__")


    # ---------- Periodic tick ----------
    def _tick(self):
        # drain inbound queue
        try:
            while True:
                s = self.in_q.get_nowait()
                if s == "__UI_CLEAR_HEADER__":
                    self.clear_console()
                    if self.link:
                        self._emit(f"⟨KISS AX.25 Terminal⟩ MYCALL={self.link.mycall}  KISS={self.link.host}:{self.link.port}")
                else:
                    self._emit(s)
        except queue.Empty:
            pass

        # update pager & badges
        self._maybe_toggle_pager()
        if self.link:
            if self.link.state == "CONNECTED":
                self._set_badge("CONNECTED", "success-inverse")
                self._set_prompt(self.link.mycall, self.link.dest)
            elif self.link.state == "AWAIT_UA":
                self._set_badge("AWAIT UA", "warning-inverse")
                self._set_prompt(self.link.mycall, None)
            else:
                self._set_badge("DISCONNECTED", "secondary-inverse")
                self._set_prompt(None, None)

        self.root.after(80, self._tick)  # ~12.5 fps

    def _set_badge(self, text: str, style: str):
        self.badge_link.configure(text=text, bootstyle=style)

    def _set_prompt(self, mycall: str | None, dest: str | None):
        # updates the small link label under the TX field
        if mycall and dest:
            self.lbl_link.configure(text=f"[{mycall} @ {dest}] >>", bootstyle="success")
        elif mycall:
            self.lbl_link.configure(text=f"[{mycall}] >>", bootstyle="warning")
        else:
            self.lbl_link.configure(text="[DISCONNECTED] >>", bootstyle="secondary")


    # ---------- History ----------
    def _push_history(self, s: str):
        if s and (not self.history or self.history[-1] != s):
            self.history.append(s)
        self.hist_idx = len(self.history)

    def _on_history_up(self, event):
        if not self.history: return "break"
        self.hist_idx = max(0, self.hist_idx - 1)
        self.entry.delete(0, "end")
        self.entry.insert(0, self.history[self.hist_idx])
        return "break"

    def _on_history_down(self, event):
        if not self.history: return "break"
        self.hist_idx = min(len(self.history), self.hist_idx + 1)
        self.entry.delete(0, "end")
        if self.hist_idx < len(self.history):
            self.entry.insert(0, self.history[self.hist_idx])
        return "break"

    # ---------- Key handlers ----------
    def _on_enter(self, event):
        self.send_line()
        return "break"

    # ---------- Cleanup ----------
    def close(self):
        try: self.logf.close()
        except Exception: pass
        if self.link:
            try: self.link.disconnect()
            except Exception: pass
            try: self.link.close()
            except Exception: pass

# =========================
# ==== Main ====
# =========================

def main():
    root = tb.Window(themename="flatly")
    app = GPTApp(root)
    def _on_close():
        app.close()
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", _on_close)
    root.mainloop()

if __name__ == "__main__":
    main()
