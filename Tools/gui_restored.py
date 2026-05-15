#!/usr/bin/env python3
"""
ShieldScan — Desktop GUI  v1.2
Windows rootkit & threat scanner with Random Forest ML and RAG filter.
"""
from __future__ import annotations

import base64
import ctypes
import glob
import hashlib
import json
import os
import queue
import re
import smtplib
import ssl
import subprocess
import sys
import threading
import webbrowser
from datetime import datetime, timedelta
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from PIL import Image, ImageDraw, ImageFont
    _PIL_OK = True
except ImportError:
    _PIL_OK = False

# ── DPI: must run before Tk() ─────────────────────────────────────────────
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

_HERE       = os.path.dirname(os.path.abspath(__file__))
_MAIN_PY    = os.path.join(_HERE, "main.py")
_LOGS       = os.path.join(_HERE, "logs")
_ECFG       = os.path.join(_HERE, "email_config.json")
_KB_JSON    = os.path.join(_HERE, "knowledge_base", "benign_entries.json")
_USERS_JSON = os.path.join(_HERE, "users.json")
_SCAN_META  = os.path.join(_HERE, "logs", "scan_meta.json")
_MODEL_META = os.path.join(_HERE, "ml_model", "model_meta.json")
_SCHED_CFG  = os.path.join(_HERE, "schedule_config.json")
_APP_CFG    = os.path.join(_HERE, "app_config.json")

_ECFG_DEFAULTS = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port":   587,
    "use_tls":     True,
    "username":    "",
    "password":    "",
    "recipient":   "",
}

_ANSI    = re.compile(r"\x1b\[[0-9;]*[mKJH]")
_RISK_RE = re.compile(r"Risk Score:\s*(\d+)/100")
_VERD_RE = re.compile(r"(CLEAN|LOW RISK|SUSPICIOUS|COMPROMISED)", re.I)

def _strip(t: str) -> str:
    return _ANSI.sub("", t)

def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

# ══════════════════════════════════════════════════════════════════════════
# Theme system
# ══════════════════════════════════════════════════════════════════════════

_THEMES: dict[str, dict] = {
    "Dark": {
        "bg":      "#0d1117",
        "surface": "#161b22",
        "card":    "#21262d",
        "card2":   "#2d333b",
        "border":  "#30363d",
        "green":   "#3fb950",
        "blue":    "#58a6ff",
        "yellow":  "#d29922",
        "red":     "#f85149",
        "orange":  "#e3b341",
        "purple":  "#bc8cff",
        "teal":    "#39c5cf",
        "pink":    "#f778ba",
        "text":    "#c9d1d9",
        "muted":   "#8b949e",
        "faint":   "#484f58",
        "white":   "#f0f6fc",
        "z_green": "#0d2b12",
        "z_blue":  "#0d1f35",
        "z_yellow":"#2b2008",
        "z_red":   "#2b0d0d",
        "accent":  "#3fb950",
    },
    "Light": {
        "bg":      "#ffffff",
        "surface": "#f6f8fa",
        "card":    "#eaeef2",
        "card2":   "#d8dee4",
        "border":  "#d0d7de",
        "green":   "#1a7f37",
        "blue":    "#0969da",
        "yellow":  "#9a6700",
        "red":     "#cf222e",
        "orange":  "#bc4c00",
        "purple":  "#8250df",
        "teal":    "#0097a7",
        "pink":    "#c2185b",
        "text":    "#1f2328",
        "muted":   "#57606a",
        "faint":   "#8c959f",
        "white":   "#24292f",
        "z_green": "#dafbe1",
        "z_blue":  "#ddf4ff",
        "z_yellow":"#fff8c5",
        "z_red":   "#ffebe9",
        "accent":  "#1a7f37",
    },
    "Midnight": {
        "bg":      "#070a12",
        "surface": "#0d1220",
        "card":    "#131b2e",
        "card2":   "#1a2540",
        "border":  "#243050",
        "green":   "#3dcfcf",
        "blue":    "#58a6ff",
        "yellow":  "#e5c07b",
        "red":     "#e06c75",
        "orange":  "#d19a66",
        "purple":  "#c678dd",
        "teal":    "#56b6c2",
        "pink":    "#e06c9f",
        "text":    "#abb2bf",
        "muted":   "#5c6370",
        "faint":   "#3e4451",
        "white":   "#c8ccd4",
        "z_green": "#0a2020",
        "z_blue":  "#0a1830",
        "z_yellow":"#2a200a",
        "z_red":   "#2a0a0c",
        "accent":  "#58a6ff",
    },
    "Solarized": {
        "bg":      "#002b36",
        "surface": "#073642",
        "card":    "#073642",
        "card2":   "#094253",
        "border":  "#0a4f63",
        "green":   "#859900",
        "blue":    "#268bd2",
        "yellow":  "#b58900",
        "red":     "#dc322f",
        "orange":  "#cb4b16",
        "purple":  "#6c71c4",
        "teal":    "#2aa198",
        "pink":    "#d33682",
        "text":    "#839496",
        "muted":   "#586e75",
        "faint":   "#3d5a63",
        "white":   "#eee8d5",
        "z_green": "#0a1a00",
        "z_blue":  "#002236",
        "z_yellow":"#261e00",
        "z_red":   "#260a00",
        "accent":  "#2aa198",
    },
}

_THEME_DOTS = {
    "Dark":      "#3fb950",
    "Light":     "#1a7f37",
    "Midnight":  "#58a6ff",
    "Solarized": "#2aa198",
}


def _load_app_cfg() -> dict:
    if os.path.exists(_APP_CFG):
        try:
            with open(_APP_CFG, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_app_cfg(cfg: dict):
    try:
        with open(_APP_CFG, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


def _detect_system_theme() -> str:
    """Read Windows AppsUseLightTheme registry key; fall back to 'Dark'."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        )
        value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        winreg.CloseKey(key)
        return "Light" if value == 1 else "Dark"
    except Exception:
        return "Dark"


def _current_theme_name() -> str:
    cfg = _load_app_cfg()
    if "theme" in cfg:
        return cfg["theme"]
    # No saved preference yet — mirror the OS light/dark setting
    detected = _detect_system_theme()
    # Persist so subsequent launches are consistent
    cfg["theme"] = detected
    _save_app_cfg(cfg)
    return detected


# ── Palette (loaded from active theme) ────────────────────────────────────
C: dict = dict(_THEMES[_current_theme_name()])

def _build_verdict_color() -> dict:
    return {
        "CLEAN":       C["green"],
        "LOW RISK":    C["blue"],
        "SUSPICIOUS":  C["yellow"],
        "COMPROMISED": C["red"],
    }

_VERDICT_COLOR: dict = _build_verdict_color()

_VERDICT_DESC = {
    "CLEAN":       "No threats detected.",
    "LOW RISK":    "Minor anomalies — review recommended.",
    "SUSPICIOUS":  "Suspicious activity — investigate.",
    "COMPROMISED": "Serious threats found — act now.",
}

_MODULES = [
    ("Process",      "Running Processes",
     "Checks for hidden or suspicious processes",
     "Compares the visible task list with low-level enumeration.\n"
     "Hidden processes are a strong rootkit indicator."),
    ("Driver",       "System Drivers",
     "Verifies loaded kernel drivers",
     "Lists all kernel-mode drivers and flags unknown or\n"
     "unsigned entries that could be rootkit components."),
    ("Network",      "Network Connections",
     "Detects unusual open ports and connections",
     "Scans all listening ports and active connections.\n"
     "Unexpected listeners can indicate backdoors."),
    ("Registry",     "Registry Entries",
     "Scans autostart registry keys for threats",
     "Checks Run/RunOnce keys and other Windows persistence\n"
     "locations for suspicious or unknown entries."),
    ("FIM",          "Critical System Files",
     "Ensures core Windows files are unmodified",
     "Hashes ~30 critical files (ntoskrnl, ntdll, lsass…)\n"
     "and alerts if any have changed since the baseline."),
    ("Persistence",  "Persistence Mechanisms",
     "Finds programs that launch at startup",
     "Scans scheduled tasks, WMI subscriptions, startup folders,\n"
     "LSA packages and services for suspicious entries."),
    ("Baseline Diff","Compare to Baseline",
     "Shows what changed since your last snapshot",
     "Compares current system state to a previously saved snapshot.\n"
     "Requires capturing a baseline first (Tools menu)."),
]

_CLI_FLAGS = {
    "Process":       "--process",
    "Driver":        "--driver",
    "Network":       "--network",
    "Registry":      "--registry",
    "FIM":           "--fim",
    "Persistence":   "--persistence",
    "Baseline Diff": "--diff",
}


# ══════════════════════════════════════════════════════════════════════════
# User management (local, no server)
# ══════════════════════════════════════════════════════════════════════════

def _hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def _load_users() -> list[dict]:
    if not os.path.exists(_USERS_JSON):
        return []
    try:
        with open(_USERS_JSON, encoding="utf-8") as f:
            return json.load(f).get("users", [])
    except Exception:
        return []

def _save_users(users: list[dict]):
    os.makedirs(os.path.dirname(_USERS_JSON), exist_ok=True)
    with open(_USERS_JSON, "w", encoding="utf-8") as f:
        json.dump({"users": users}, f, indent=2)

def _find_user(username: str) -> dict | None:
    for u in _load_users():
        if u.get("username", "").lower() == username.lower():
            return u
    return None

def _register_user(username: str, email: str, password: str) -> str | None:
    """Return None on success, error string on failure."""
    if not username.strip():
        return "Username cannot be empty."
    if "@" not in email or "." not in email:
        return "Enter a valid email address."
    if len(password) < 6:
        return "Password must be at least 6 characters."
    users = _load_users()
    if any(u["username"].lower() == username.lower() for u in users):
        return "Username already taken."
    if any(u["email"].lower() == email.lower() for u in users):
        return "Email already registered."
    users.append({
        "username": username.strip(),
        "email":    email.strip().lower(),
        "password_hash": _hash_pw(password),
        "created_at": datetime.now().isoformat(),
    })
    _save_users(users)
    return None

def _authenticate(username: str, password: str) -> dict | None:
    """Return user dict on success, None on failure."""
    u = _find_user(username)
    if u and u.get("password_hash") == _hash_pw(password):
        return u
    return None

# ── Scan metadata (per-user tagging) ──────────────────────────────────────

def _load_scan_meta() -> dict:
    if not os.path.exists(_SCAN_META):
        return {}
    try:
        with open(_SCAN_META, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_scan_meta(meta: dict):
    os.makedirs(os.path.dirname(_SCAN_META), exist_ok=True)
    with open(_SCAN_META, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

def _tag_report(filename: str, user: str, score: int = 0, verdict: str = ""):
    meta = _load_scan_meta()
    meta[os.path.basename(filename)] = {
        "user":    user,
        "score":   score,
        "verdict": verdict,
        "ts":      datetime.now().isoformat(),
    }
    _save_scan_meta(meta)


# ── Schedule helpers ──────────────────────────────────────────────────────

def _load_schedules() -> dict:
    if not os.path.exists(_SCHED_CFG):
        return {}
    try:
        with open(_SCHED_CFG, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_schedules(data: dict):
    with open(_SCHED_CFG, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def _next_run_for(mode: str, time_str: str,
                  days: list[int], interval_h: int) -> datetime:
    """Calculate the next datetime for a schedule."""
    now = datetime.now()
    try:
        hh, mm = (int(x) for x in time_str.split(":"))
    except Exception:
        hh, mm = 9, 0

    if mode == "interval":
        from datetime import timedelta
        return now.replace(second=0, microsecond=0) + timedelta(hours=max(1, interval_h))

    if mode == "daily":
        candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if candidate <= now:
            from datetime import timedelta
            candidate += timedelta(days=1)
        return candidate

    if mode == "weekly":
        from datetime import timedelta
        if not days:
            days = list(range(7))
        for offset in range(1, 8):
            candidate = (now + timedelta(days=offset)).replace(
                hour=hh, minute=mm, second=0, microsecond=0)
            if candidate.weekday() in days:
                return candidate
        return now + timedelta(days=7)

    # once — just use time today or tomorrow
    candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if candidate <= now:
        from datetime import timedelta
        candidate += timedelta(days=1)
    return candidate


# ══════════════════════════════════════════════════════════════════════════
# Tooltip
# ══════════════════════════════════════════════════════════════════════════

class Tooltip:
    def __init__(self, widget: tk.Widget, text: str):
        self._w, self._text = widget, text
        self._win: tk.Toplevel | None = None
        self._job: str | None = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._cancel,   add="+")

    def _schedule(self, _=None):
        self._cancel()
        self._job = self._w.after(500, self._show)

    def _cancel(self, _=None):
        if self._job:
            self._w.after_cancel(self._job);  self._job = None
        if self._win:
            self._win.destroy();  self._win = None

    def _show(self):
        if self._win:
            return
        x = self._w.winfo_rootx() + 14
        y = self._w.winfo_rooty() + self._w.winfo_height() + 4
        self._win = tk.Toplevel(self._w)
        self._win.wm_overrideredirect(True)
        self._win.wm_geometry(f"+{x}+{y}")
        self._win.attributes("-topmost", True)
        f = tk.Frame(self._win, bg=C["card2"],
                     highlightbackground=C["border"],
                     highlightthickness=1)
        f.pack()
        tk.Label(f, text=self._text,
                 bg=C["card2"], fg=C["text"],
                 font=("Segoe UI", 8),
                 padx=10, pady=6,
                 justify=tk.LEFT,
                 wraplength=280).pack()


# ══════════════════════════════════════════════════════════════════════════
# App
# ══════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    VERSION = "v1.2"

    def __init__(self, username: str = "Guest", email: str = ""):
        super().__init__()
        self._current_user  = username
        self._current_email = email

        # DPI
        dpi = self.winfo_fpixels("1i")
        self._scale = max(1.0, dpi / 96.0)
        try:
            self.tk.call("tk", "scaling", dpi / 72.0)
        except Exception:
            pass

        self.geometry(f"{int(1240*self._scale)}x{int(800*self._scale)}")
        self.minsize(int(960*self._scale), int(640*self._scale))
        self.title("ShieldScan")
        self.configure(bg=C["bg"])

        # Win 11 dark title bar
        try:
            self.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            if hwnd:
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, 20, ctypes.byref(ctypes.c_int(1)),
                    ctypes.sizeof(ctypes.c_int))
        except Exception:
            pass

        # ttk scrollbar style
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Slim.Vertical.TScrollbar",
                        gripcount=0,
                        background=C["card2"],
                        darkcolor=C["card2"],
                        lightcolor=C["card2"],
                        troughcolor=C["bg"],
                        bordercolor=C["bg"],
                        arrowcolor=C["faint"],
                        arrowsize=8,
                        relief="flat",
                        borderwidth=0)
        style.map("Slim.Vertical.TScrollbar",
                  background=[("active", C["border"]),
                               ("pressed", C["muted"])])

        # State
        self._proc: subprocess.Popen | None = None
        self._scanning    = False
        self._last_report: str | None = None
        self._q: queue.Queue = queue.Queue()
        self._scan_start: datetime | None = None

        self._mods = {
            mid: tk.BooleanVar(value=(mid != "Baseline Diff"))
            for mid, *_ in _MODULES
        }
        self._no_ml     = tk.BooleanVar(value=False)
        self._no_report = tk.BooleanVar(value=False)
        self._watch     = tk.StringVar(value="0")

        self._score   = 0
        self._verdict = ""

        self._sv_status  = tk.StringVar(value="Ready")
        self._sv_elapsed = tk.StringVar(value="")

        # Logout / restart flags — checked by main() after mainloop() returns
        self._logout_requested  = False
        self._restart_requested = False
        self._active_theme      = _current_theme_name()

        # Tray icon handle (filled in _start_tray if pystray available)
        self._tray_icon = None

        # Scheduled-scan state
        self._is_scheduled_scan = False
        self._sched_cfg: dict   = {}
        self._sched_next: datetime | None = None
        self._sv_sched_next = tk.StringVar(value="—")
        self._sv_sched_status = tk.StringVar(value="Off")

        # Build
        self._active_tab_btn: tk.Button | None = None

        # Initialise before _build_body so _on_scan_done / _refresh_history
        # can never hit AttributeError even if called very early.
        self._hist_selected: dict[str, tk.BooleanVar] = {}
        self._cmp_btn: tk.Button | None = None

        self._build_menu()
        self._build_topbar()
        self._build_body()
        self._build_statusbar()
        self._poll_queue()

        # Load and arm any saved schedule for this user
        self._load_user_schedule()
        self._schedule_tick()

        # Activate the Output tab by default
        self._switch_tab("output")
        self._show_welcome(warn_admin=not _is_admin())

        # Keyboard shortcuts
        self._bind_shortcuts()

        # System tray icon (graceful degradation)
        self._start_tray()

    # ══════════════════════════════════════════════════════════
    # Menu
    # ══════════════════════════════════════════════════════════

    def _build_menu(self):
        def _m(p, **kw):
            return tk.Menu(p, tearoff=False,
                           bg=C["card"], fg=C["text"],
                           activebackground=C["green"],
                           activeforeground=C["bg"], **kw)
        bar = _m(self);  self.config(menu=bar)

        mf = _m(bar)
        mf.add_command(label="Open Last Report",          command=self._open_report)
        mf.add_command(label="Send Last Report by Email", command=self._send_report_email)
        mf.add_command(label="Save Report as Image…",     command=self._save_report_image)
        mf.add_command(label="Export Findings as CSV…",   command=self._export_csv)
        mf.add_separator()
        mf.add_command(label="Open Logs Folder",          command=self._open_logs)
        mf.add_separator()
        mf.add_command(label="Settings…",                 command=self._settings_dialog)
        mf.add_separator()
        mf.add_command(label="Exit", command=self.destroy)
        bar.add_cascade(label="File", menu=mf)

        mt = _m(bar)
        mt.add_command(label="Analyze Memory Dump…",  command=self._analyze_dump)
        mt.add_command(label="Schedule Scan…",        command=self._schedule_dialog)
        mt.add_separator()
        mt.add_command(label="Capture Baseline",      command=self._capture_baseline)
        mt.add_command(label="List Baselines",        command=self._list_baselines)
        mt.add_separator()
        mt.add_command(label="Update ML (built-in)",  command=lambda: self._update_ml(False))
        mt.add_command(label="Update ML + Kaggle",    command=lambda: self._update_ml(True))
        mt.add_separator()
        mt.add_command(label="Reset FIM Baseline",    command=self._reset_fim)
        mt.add_separator()
        mt.add_command(label="Email Settings",        command=self._email_settings_dialog)
        mt.add_command(label="Configure RAG Filter KB",
                       command=lambda: os.startfile(_KB_JSON)
                       if os.path.exists(_KB_JSON)
                       else messagebox.showinfo("RAG Filter",
                           f"Knowledge base not found:\n{_KB_JSON}"))
        bar.add_cascade(label="Tools", menu=mt)

        mh = _m(bar)
        mh.add_command(label="How to Use",   command=self._show_howto)
        mh.add_command(label="Model Info",   command=lambda: self._switch_tab("model"))
        mh.add_separator()
        mh.add_command(label="About",        command=self._about)
        bar.add_cascade(label="Help", menu=mh)

    # ══════════════════════════════════════════════════════════
    # Top bar
    # ══════════════════════════════════════════════════════════

    def _build_topbar(self):
        bar = tk.Frame(self, bg=C["surface"])
        bar.pack(fill=tk.X)
        tk.Frame(bar, bg=C["border"], height=1).pack(side=tk.BOTTOM, fill=tk.X)

        # ── Logo (left) ───────────────────────────────────────
        logo = tk.Frame(bar, bg=C["surface"])
        logo.pack(side=tk.LEFT, padx=(20, 0), pady=12)
        tk.Label(logo, text="Shield", fg=C["white"], bg=C["surface"],
                 font=("Segoe UI", 13, "bold")).pack(side=tk.LEFT)
        tk.Label(logo, text="Scan",   fg=C["accent"], bg=C["surface"],
                 font=("Segoe UI", 13, "bold")).pack(side=tk.LEFT)
        tk.Label(logo, text=f"  {self.VERSION}", fg=C["faint"],
                 bg=C["surface"], font=("Segoe UI", 8)).pack(side=tk.LEFT, pady=(5, 0))

        # ── Right cluster ─────────────────────────────────────
        right = tk.Frame(bar, bg=C["surface"])
        right.pack(side=tk.RIGHT, padx=(0, 16), pady=8)

        # Action buttons
        self._run_btn = self._hbtn(right, "  ▶  Run Scan  ",
                                    self._run_scan,
                                    fg=C["bg"], bg=C["accent"])
        self._run_btn.pack(side=tk.RIGHT, padx=(4, 0))
        Tooltip(self._run_btn, "Start scan  (Ctrl+R)")

        self._stop_btn = self._hbtn(right, "  ■  Stop  ",
                                     self._stop_scan,
                                     fg=C["red"], bg=C["card2"])
        self._stop_btn.pack(side=tk.RIGHT, padx=(4, 0))
        self._stop_btn.configure(state=tk.DISABLED)
        Tooltip(self._stop_btn, "Stop running scan  (Ctrl+.)")

        # Divider
        tk.Frame(right, bg=C["border"], width=1).pack(
            side=tk.RIGHT, fill=tk.Y, padx=(8, 8), pady=4)

        # Logout
        logout_btn = tk.Button(right, text="⏏  Logout",
                               command=self._logout,
                               bg=C["surface"], fg=C["muted"],
                               activebackground=C["card"],
                               activeforeground=C["white"],
                               font=("Segoe UI", 8),
                               relief=tk.FLAT, bd=0,
                               padx=8, pady=6, cursor="hand2")
        logout_btn.pack(side=tk.RIGHT, padx=(0, 4))
        logout_btn.bind("<Enter>", lambda _: logout_btn.configure(
            fg=C["white"], bg=C["card"]))
        logout_btn.bind("<Leave>", lambda _: logout_btn.configure(
            fg=C["muted"], bg=C["surface"]))
        Tooltip(logout_btn, "Sign out and return to login screen.")

        # Admin badge
        admin_ok = _is_admin()
        badge = tk.Label(right,
                         text=f"● {'Admin' if admin_ok else 'Limited'}",
                         fg=C["green"] if admin_ok else C["yellow"],
                         bg=C["surface"], font=("Segoe UI", 8))
        badge.pack(side=tk.RIGHT, padx=(0, 8))
        Tooltip(badge,
                "Running as Administrator — all modules available."
                if admin_ok else
                "Limited access. Relaunch via launch.bat for full coverage.")

        # User pill
        initials = (self._current_user[:2]).upper() if self._current_user else "?"
        user_pill = tk.Frame(right, bg=C["card2"], padx=6, pady=3)
        user_pill.pack(side=tk.RIGHT, padx=(0, 8))
        tk.Label(user_pill, text=initials,
                 fg=C["accent"], bg=C["card2"],
                 font=("Segoe UI", 8, "bold")).pack(side=tk.LEFT)
        tk.Label(user_pill, text=f"  {self._current_user}",
                 fg=C["text"], bg=C["card2"],
                 font=("Segoe UI", 8)).pack(side=tk.LEFT)
        Tooltip(user_pill, f"Signed in as: {self._current_user}\n{self._current_email}")

        # Divider
        tk.Frame(right, bg=C["border"], width=1).pack(
            side=tk.RIGHT, fill=tk.Y, padx=(8, 8), pady=4)

        # Theme picker
        theme_btn = tk.Button(right, text="◑  Theme",
                              command=self._theme_picker,
                              bg=C["surface"], fg=C["muted"],
                              activebackground=C["card"],
                              activeforeground=C["text"],
                              font=("Segoe UI", 8),
                              relief=tk.FLAT, bd=0,
                              padx=8, pady=6, cursor="hand2")
        theme_btn.pack(side=tk.RIGHT, padx=(0, 4))
        theme_btn.bind("<Enter>", lambda _: theme_btn.configure(
            fg=C["text"], bg=C["card"]))
        theme_btn.bind("<Leave>", lambda _: theme_btn.configure(
            fg=C["muted"], bg=C["surface"]))
        Tooltip(theme_btn, "Switch colour theme.")
        # Keep ref so _theme_picker can anchor itself under this button
        self._theme_btn_ref = theme_btn

    def _hbtn(self, parent, text, cmd, fg, bg) -> tk.Button:
        b = tk.Button(parent, text=text, command=cmd,
                      bg=bg, fg=fg,
                      activebackground=C["card2"],
                      activeforeground=C["white"],
                      font=("Segoe UI", 9, "bold"),
                      relief=tk.FLAT, bd=0,
                      padx=4, pady=6, cursor="hand2")
        hbg = "#4ac760" if bg == C["green"] else C["border"]
        b.bind("<Enter>", lambda _: b.configure(bg=hbg))
        b.bind("<Leave>", lambda _: b.configure(bg=bg))
        return b

    # ══════════════════════════════════════════════════════════
    # Body — 3 columns
    # ══════════════════════════════════════════════════════════

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill=tk.BOTH, expand=True)

        self._build_left(body).pack(side=tk.LEFT, fill=tk.Y)
        tk.Frame(body, bg=C["border"], width=1).pack(
            side=tk.LEFT, fill=tk.Y)

        self._center_host = tk.Frame(body, bg=C["bg"])
        self._center_host.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Frame(body, bg=C["border"], width=1).pack(
            side=tk.LEFT, fill=tk.Y)
        self._build_right(body).pack(side=tk.LEFT, fill=tk.Y)

        self._welcome_panel = self._build_welcome_panel(self._center_host)
        self._output_panel  = self._build_output_panel(self._center_host)

    # ══════════════════════════════════════════════════════════
    # Left panel
    # ══════════════════════════════════════════════════════════

    def _build_left(self, parent) -> tk.Frame:
        outer = tk.Frame(parent, bg=C["surface"], width=270)
        outer.pack_propagate(False)
        inner = tk.Frame(outer, bg=C["surface"])
        inner.pack(fill=tk.BOTH, expand=True, padx=16)

        # ── Scan mode selector ────────────────────────────────
        self._slabel(inner, "SCAN MODE")
        mode_row = tk.Frame(inner, bg=C["surface"])
        mode_row.pack(fill=tk.X, pady=(0, 8))
        mode_row.columnconfigure(0, weight=1)
        mode_row.columnconfigure(1, weight=1)
        mode_row.columnconfigure(2, weight=1)

        self._scan_mode = tk.StringVar(value="Full")
        for col, (mode, label, tip) in enumerate((
            ("Quick",  "⚡ Quick",  "Process + Network only (~10s)"),
            ("Full",   "🔍 Full",   "All 7 modules — recommended (~60s)"),
            ("Custom", "⚙ Custom", "Choose modules manually below"),
        )):
            b = tk.Button(mode_row, text=label,
                          command=lambda m=mode: self._set_scan_mode(m),
                          bg=C["card2"] if mode == "Full" else C["card"],
                          fg=C["white"] if mode == "Full" else C["muted"],
                          activebackground=C["card2"],
                          activeforeground=C["white"],
                          font=("Segoe UI", 8, "bold"),
                          relief=tk.FLAT, bd=0,
                          pady=6, cursor="hand2")
            b.grid(row=0, column=col, sticky="ew", padx=1)
            Tooltip(b, tip)
            setattr(self, f"_mode_btn_{mode.lower()}", b)

        self._hsep(inner, pad=8)

        # Header row with Select All / None
        hrow = tk.Frame(inner, bg=C["surface"])
        hrow.pack(fill=tk.X, pady=(16, 0))
        tk.Label(hrow, text="WHAT TO SCAN",
                 fg=C["muted"], bg=C["surface"],
                 font=("Segoe UI", 7, "bold")).pack(side=tk.LEFT)
        for txt, fn in (("All", self._select_all),
                        ("None", self._clear_all)):
            b = tk.Button(hrow, text=txt, command=fn,
                          bg=C["surface"], fg=C["faint"],
                          activebackground=C["card"],
                          activeforeground=C["text"],
                          font=("Segoe UI", 7), relief=tk.FLAT,
                          bd=0, padx=6, pady=1, cursor="hand2")
            b.pack(side=tk.RIGHT, padx=2)
            b.bind("<Enter>", lambda e, w=b: w.configure(
                fg=C["text"], bg=C["card"]))
            b.bind("<Leave>", lambda e, w=b: w.configure(
                fg=C["faint"], bg=C["surface"]))

        tk.Label(inner,
                 text="Click a module to toggle it on or off.",
                 fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 7),
                 anchor="w").pack(fill=tk.X, pady=(4, 8))

        for mid, name, desc, tip in _MODULES:
            self._mod_row(inner, mid, name, desc, tip, self._mods[mid])

        # Options
        self._hsep(inner)
        self._slabel(inner, "OPTIONS")
        self._optrow(inner, "Skip ML Threat Analysis", self._no_ml,
                     "Faster scan — skips the AI threat classifier.")
        self._optrow(inner, "Skip HTML Report", self._no_report,
                     "Do not save an HTML report after the scan.")

        wf = tk.Frame(inner, bg=C["surface"])
        wf.pack(fill=tk.X, pady=(10, 0))
        wl = tk.Label(wf, text="Watch Mode (seconds)",
                      fg=C["muted"], bg=C["surface"],
                      font=("Segoe UI", 8))
        wl.pack(side=tk.LEFT)
        Tooltip(wl, "Enter a number > 0 to re-scan every N seconds.\n"
                    "Only new findings are reported in watch mode.")
        tk.Entry(wf, textvariable=self._watch, width=5,
                 bg=C["card"], fg=C["text"],
                 insertbackground=C["text"],
                 relief=tk.FLAT, font=("Consolas", 9),
                 highlightthickness=1,
                 highlightcolor=C["green"],
                 highlightbackground=C["border"]).pack(side=tk.RIGHT)

        # Tools
        self._hsep(inner)
        self._slabel(inner, "TOOLS")
        for label, cmd, tip in (
            ("Capture Baseline",
             self._capture_baseline,
             "Save a snapshot of the current system state.\n"
             "Used as a reference for 'Compare to Baseline'."),
            ("List Saved Baselines",
             self._list_baselines,
             "Show all previously saved snapshots."),
            ("Update ML Model",
             lambda: self._update_ml(False),
             "Retrain the AI threat classifier."),
            ("Reset File Integrity Baseline",
             self._reset_fim,
             "Clear saved file hashes — next scan creates new ones."),
            ("Open Scan Logs Folder",
             self._open_logs,
             "Open the folder containing scan logs and reports."),
        ):
            self._toolbtn(inner, label, cmd, tip)

        # Sync button highlight with the default scan mode
        self.after(0, lambda: self._set_scan_mode("Full"))

        return outer

    def _mod_row(self, parent, mid: str, name: str,
                 desc: str, tip: str, var: tk.BooleanVar):
        row = tk.Frame(parent, bg=C["surface"], cursor="hand2")
        row.pack(fill=tk.X, pady=1)

        accent = tk.Frame(row, width=3, bg=C["surface"])
        accent.pack(side=tk.LEFT, fill=tk.Y)

        body = tk.Frame(row, bg=C["surface"])
        body.pack(side=tk.LEFT, fill=tk.X, expand=True,
                  padx=(10, 8), pady=8)

        top = tk.Frame(body, bg=C["surface"])
        top.pack(fill=tk.X)

        dot   = tk.Label(top, text="●", bg=C["surface"],
                          font=("Segoe UI", 9))
        dot.pack(side=tk.LEFT)

        namel = tk.Label(top, text=f"  {name}", bg=C["surface"],
                          font=("Segoe UI", 9, "bold"))
        namel.pack(side=tk.LEFT)

        badge = tk.Label(top, bg=C["surface"],
                          font=("Segoe UI", 7, "bold"))
        badge.pack(side=tk.RIGHT)

        descl = tk.Label(body, text=desc, bg=C["surface"],
                          fg=C["faint"], font=("Segoe UI", 8),
                          anchor="w")
        descl.pack(fill=tk.X, pady=(3, 0))

        _all = [row, accent, body, top, dot, namel, badge, descl]
        Tooltip(row, tip)

        def _refresh(*_):
            on = var.get()
            accent.configure(bg=C["green"] if on else C["surface"])
            dot.configure(fg=C["green"] if on else C["faint"])
            namel.configure(fg=C["text"] if on else C["muted"])
            badge.configure(text="ON" if on else "OFF",
                            fg=C["green"] if on else C["faint"])
            descl.configure(fg=C["muted"] if on else C["faint"])

        def _toggle(_=None): var.set(not var.get())

        def _enter(_):
            for w in _all:
                if w is not accent:
                    try: w.configure(bg=C["card"])
                    except Exception: pass

        def _leave(_):
            for w in _all:
                if w is not accent:
                    try: w.configure(bg=C["surface"])
                    except Exception: pass

        var.trace_add("write", _refresh);  _refresh()
        for w in _all:
            w.bind("<Button-1>", _toggle)
            w.bind("<Enter>",    _enter)
            w.bind("<Leave>",    _leave)

    def _optrow(self, parent, label: str, var: tk.BooleanVar,
                tip: str = ""):
        f = tk.Frame(parent, bg=C["surface"], cursor="hand2")
        f.pack(fill=tk.X, pady=3)
        box = tk.Label(f, text="  ", width=2, bg=C["card"],
                       font=("Consolas", 8))
        box.pack(side=tk.LEFT)
        lbl = tk.Label(f, text=label, fg=C["muted"], bg=C["surface"],
                       font=("Segoe UI", 9))
        lbl.pack(side=tk.LEFT, padx=(8, 0))
        if tip: Tooltip(f, tip)

        def _ref(*_):
            if var.get():
                box.configure(bg=C["green"], text="✓", fg=C["bg"])
                lbl.configure(fg=C["text"])
            else:
                box.configure(bg=C["card"], text="  ", fg=C["card"])
                lbl.configure(fg=C["muted"])
        var.trace_add("write", _ref);  _ref()
        for w in (f, box, lbl):
            w.bind("<Button-1>", lambda _: var.set(not var.get()))

    def _toolbtn(self, parent, label: str, cmd, tip: str = ""):
        b = tk.Button(parent, text=label, command=cmd,
                      bg=C["surface"], fg=C["muted"],
                      activebackground=C["card"],
                      activeforeground=C["text"],
                      font=("Segoe UI", 9), relief=tk.FLAT,
                      bd=0, pady=5, anchor="w", cursor="hand2")
        b.pack(fill=tk.X, pady=1)
        b.bind("<Enter>", lambda _: b.configure(fg=C["text"], bg=C["card"]))
        b.bind("<Leave>", lambda _: b.configure(fg=C["muted"], bg=C["surface"]))
        if tip: Tooltip(b, tip)

    def _slabel(self, parent, text: str):
        tk.Label(parent, text=text, fg=C["muted"], bg=C["surface"],
                 font=("Segoe UI", 8, "bold"),
                 anchor="w").pack(fill=tk.X, pady=(0, 6))

    def _hsep(self, parent, pad: int = 10):
        tk.Frame(parent, bg=C["border"], height=1).pack(
            fill=tk.X, pady=pad)

    def _select_all(self):
        for v in self._mods.values(): v.set(True)

    def _clear_all(self):
        for v in self._mods.values(): v.set(False)

    # ══════════════════════════════════════════════════════════
    # Centre — welcome panel
    # ══════════════════════════════════════════════════════════

    def _build_welcome_panel(self, parent) -> tk.Frame:
        panel = tk.Frame(parent, bg=C["bg"])

        shdr = tk.Frame(panel, bg=C["surface"])
        shdr.pack(fill=tk.X)
        tk.Frame(shdr, bg=C["border"], height=1).pack(
            side=tk.BOTTOM, fill=tk.X)
        tk.Label(shdr, text="Welcome",
                 fg=C["text"], bg=C["surface"],
                 font=("Segoe UI", 10, "bold"),
                 padx=20, pady=10).pack(side=tk.LEFT)

        wrap = tk.Frame(panel, bg=C["bg"])
        wrap.place(relx=0.5, rely=0.46, anchor="center")

        tk.Label(wrap, text="🛡", bg=C["bg"],
                 font=("Segoe UI", 46)).pack(pady=(0, 12))

        tk.Label(wrap, text="ShieldScan",
                 fg=C["white"], bg=C["bg"],
                 font=("Segoe UI", 18, "bold")).pack()

        tk.Label(wrap,
                 text="Scan your Windows system for hidden threats, suspicious\n"
                      "processes, unusual network activity and persistence mechanisms.",
                 fg=C["muted"], bg=C["bg"],
                 font=("Segoe UI", 10), justify=tk.CENTER).pack(pady=(8, 28))

        # 3-step cards
        cards = tk.Frame(wrap, bg=C["bg"])
        cards.pack()
        for col, (num, title, body, icon) in enumerate((
            ("1", "Choose Modules",
             "Select what to scan\nin the left panel.", "☰"),
            ("2", "Run the Scan",
             "Click  Run Scan  in\nthe top-right.", "▶"),
            ("3", "Review Results",
             "Findings appear here\nin real time.", "◎"),
        )):
            # Outer = accent top border
            c_outer = tk.Frame(cards, bg=C["green"])
            c_outer.grid(row=0, column=col, padx=8, sticky="nsew")
            cards.columnconfigure(col, weight=1)
            tk.Frame(c_outer, bg=C["green"], height=3).pack(fill=tk.X)
            c = tk.Frame(c_outer, bg=C["surface"])
            c.pack(fill=tk.BOTH, expand=True)
            inner = tk.Frame(c, bg=C["surface"])
            inner.pack(fill=tk.X, padx=18, pady=14)
            # Step badge row
            badge_row = tk.Frame(inner, bg=C["surface"])
            badge_row.pack(fill=tk.X, pady=(0, 10))
            tk.Label(badge_row, text=f" {num} ", fg=C["bg"], bg=C["green"],
                     font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
            tk.Label(badge_row, text=f"  {icon}", fg=C["accent"], bg=C["surface"],
                     font=("Segoe UI", 12)).pack(side=tk.LEFT)
            tk.Label(inner, text=title, fg=C["white"], bg=C["surface"],
                     font=("Segoe UI", 10, "bold")).pack(anchor="w")
            tk.Label(inner, text=body, fg=C["muted"], bg=C["surface"],
                     font=("Segoe UI", 8), justify=tk.LEFT).pack(anchor="w", pady=(5, 0))

        # ── Compact ML model status card ─────────────────────
        ml_card = tk.Frame(wrap, bg=C["card"], pady=0)
        ml_card.pack(fill=tk.X, pady=(20, 0))
        tk.Frame(ml_card, bg=C["border"], height=1).pack(fill=tk.X)
        ml_inner = tk.Frame(ml_card, bg=C["card"])
        ml_inner.pack(fill=tk.X, padx=16, pady=10)

        ml_title = tk.Frame(ml_inner, bg=C["card"])
        ml_title.pack(fill=tk.X)
        tk.Label(ml_title, text="🤖  ML Classifier",
                 fg=C["purple"], bg=C["card"],
                 font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        view_btn = tk.Button(ml_title, text="View Details →",
                             command=lambda: (self._show_output(),
                                             self._switch_tab("model")),
                             bg=C["card"], fg=C["blue"],
                             activebackground=C["card2"],
                             activeforeground=C["white"],
                             font=("Segoe UI", 8), relief=tk.FLAT,
                             bd=0, cursor="hand2")
        view_btn.pack(side=tk.RIGHT)
        view_btn.bind("<Enter>", lambda _: view_btn.configure(fg=C["white"]))
        view_btn.bind("<Leave>", lambda _: view_btn.configure(fg=C["blue"]))

        self._welcome_ml_frame = tk.Frame(ml_inner, bg=C["card"])
        self._welcome_ml_frame.pack(fill=tk.X, pady=(6, 0))
        self._refresh_welcome_ml()

        # Admin warning
        self._warn_lbl = tk.Label(
            wrap,
            text="⚠  Not running as Administrator — some scans will be limited.\n"
                 "   Close and relaunch via launch.bat or right-click → Run as administrator.",
            fg=C["yellow"], bg=C["card"],
            font=("Segoe UI", 9), padx=16, pady=10,
            justify=tk.LEFT)

        return panel

    def _refresh_welcome_ml(self):
        """Populate the compact ML info card on the welcome screen."""
        for w in self._welcome_ml_frame.winfo_children():
            w.destroy()
        meta: dict = {}
        if os.path.exists(_MODEL_META):
            try:
                with open(_MODEL_META, encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                pass

        if not meta:
            tk.Label(self._welcome_ml_frame,
                     text="Model not trained yet — click 'Update ML Model' in Tools.",
                     fg=C["muted"], bg=C["card"],
                     font=("Segoe UI", 8)).pack(anchor="w")
            return

        acc      = meta.get("cv_accuracy", 0)
        f1       = meta.get("f1_macro", 0)
        auc      = meta.get("auc_roc", 0)
        trained  = meta.get("trained_at", "")
        try:
            trained = datetime.fromisoformat(trained).strftime("%d %b %Y")
        except Exception:
            trained = trained[:10] if trained else "—"

        rows = [
            ("Architecture", "Random Forest  (500 trees, balanced)", "green"),
            ("CV Accuracy",  f"{acc:.1%}", "blue"),
            ("F1 Macro",     f"{f1:.3f}", "blue"),
            ("AUC-ROC",      f"{auc:.3f}" if auc else "—", "purple"),
            ("Trained",      trained, "faint"),
            ("Classes",      str(meta.get("classes", "—")), "faint"),
        ]
        grid = tk.Frame(self._welcome_ml_frame, bg=C["card"])
        grid.pack(fill=tk.X)
        for i, (k, v, vc) in enumerate(rows):
            col = i % 3
            row = i // 3
            cell = tk.Frame(grid, bg=C["card"])
            cell.grid(row=row, column=col, sticky="w", padx=(0, 20), pady=2)
            tk.Label(cell, text=k + ":", fg=C["faint"], bg=C["card"],
                     font=("Segoe UI", 7)).pack(side=tk.LEFT)
            tk.Label(cell, text="  " + v, fg=C[vc], bg=C["card"],
                     font=("Segoe UI", 8, "bold")).pack(side=tk.LEFT)

    def _show_welcome(self, warn_admin: bool = False):
        self._output_panel.pack_forget()
        self._welcome_panel.pack(fill=tk.BOTH, expand=True)
        if warn_admin:
            self._warn_lbl.pack(pady=(20, 0))
        else:
            self._warn_lbl.pack_forget()

    def _show_output(self):
        self._welcome_panel.pack_forget()
        self._output_panel.pack(fill=tk.BOTH, expand=True)

    # ══════════════════════════════════════════════════════════
    # Centre — output panel
    # ══════════════════════════════════════════════════════════

    def _build_output_panel(self, parent) -> tk.Frame:
        panel = tk.Frame(parent, bg=C["bg"])

        # ── Tab header ────────────────────────────────────────
        shdr = tk.Frame(panel, bg=C["surface"])
        shdr.pack(fill=tk.X)
        tk.Frame(shdr, bg=C["border"], height=1).pack(
            side=tk.BOTTOM, fill=tk.X)

        # Tab buttons
        self._tab_out_btn = self._tab_btn(
            shdr, "Scan Output", lambda: self._switch_tab("output"))
        self._tab_out_btn.pack(side=tk.LEFT)
        self._tab_hist_btn = self._tab_btn(
            shdr, "History", lambda: self._switch_tab("history"))
        self._tab_hist_btn.pack(side=tk.LEFT)
        self._tab_model_btn = self._tab_btn(
            shdr, "Model Info", lambda: self._switch_tab("model"))
        self._tab_model_btn.pack(side=tk.LEFT)
        self._tab_dash_btn = self._tab_btn(
            shdr, "📊 Dashboard", lambda: self._switch_tab("dashboard"))
        self._tab_dash_btn.pack(side=tk.LEFT)
        self._tab_about_btn = self._tab_btn(
            shdr, "ℹ About", lambda: self._switch_tab("about"))
        self._tab_about_btn.pack(side=tk.LEFT)

        # Active-tab underline bar
        self._tab_bar = tk.Frame(shdr, bg=C["green"], height=2)

        tk.Label(shdr, textvariable=self._sv_elapsed,
                 fg=C["faint"], bg=C["surface"],
                 font=("Consolas", 8)).pack(side=tk.LEFT, padx=(8, 0))

        clr = tk.Button(shdr, text="Clear",
                        command=self._clear_output,
                        bg=C["surface"], fg=C["faint"],
                        activebackground=C["card"],
                        activeforeground=C["text"],
                        font=("Segoe UI", 8),
                        relief=tk.FLAT, bd=0,
                        padx=14, pady=8, cursor="hand2")
        clr.pack(side=tk.RIGHT)
        clr.bind("<Enter>", lambda _: clr.configure(
            fg=C["text"], bg=C["card"]))
        clr.bind("<Leave>", lambda _: clr.configure(
            fg=C["faint"], bg=C["surface"]))

        # ── Summary + progress bar (container, hidden until scan) ──────
        # Store as one container so we never hit the "not packed" error.
        self._scan_info = tk.Frame(panel, bg=C["bg"])
        # NOTE: NOT packed here — packed in _run_scan

        # Summary bar inside container
        sumbar = tk.Frame(self._scan_info, bg=C["card"])
        sumbar.pack(fill=tk.X)
        tk.Frame(sumbar, bg=C["border"], height=1).pack(
            side=tk.BOTTOM, fill=tk.X)
        sb = tk.Frame(sumbar, bg=C["card"])
        sb.pack(fill=tk.X, padx=20, pady=9)
        self._lbl_scan_msg = tk.Label(sb, text="",
                                       fg=C["muted"], bg=C["card"],
                                       font=("Segoe UI", 9))
        self._lbl_scan_msg.pack(side=tk.LEFT)
        self._pills: dict[str, tk.Label] = {}
        for sev, ck in (("HIGH","red"),("MED","yellow"),("LOW","blue")):
            p = tk.Label(sb, text=f"  {sev}  0  ",
                         fg=C[ck], bg=C["card2"],
                         font=("Segoe UI", 8, "bold"))
            p.pack(side=tk.RIGHT, padx=(6, 0))
            Tooltip(p, {"HIGH": "Critical threats — act immediately.",
                        "MED":  "Moderate issues — investigate soon.",
                        "LOW":  "Low-risk anomalies."}[sev])
            self._pills[sev] = p

        # Progress bar inside container
        self._prog = tk.Canvas(self._scan_info, height=3,
                                bg=C["card2"],
                                highlightthickness=0, bd=0)
        self._prog.pack(fill=tk.X)
        self._prog.bind("<Configure>", lambda _: self._draw_progress())

        # ── History frame (swapped in by tab click) ──────────
        self._history_tf = tk.Frame(panel, bg=C["bg"])
        # NOT packed initially
        self._build_history_frame(self._history_tf)

        # ── Model info frame ──────────────────────────────────
        self._model_tf = tk.Frame(panel, bg=C["bg"])
        # NOT packed initially
        self._build_model_frame(self._model_tf)

        # ── Dashboard frame ───────────────────────────────────
        self._dash_tf = tk.Frame(panel, bg=C["bg"])
        # NOT packed initially
        self._build_dashboard_tab(self._dash_tf)

        # ── About frame ───────────────────────────────────────
        self._about_tf = tk.Frame(panel, bg=C["bg"])
        # NOT packed initially
        self._build_about_tab(self._about_tf)

        # ── Text output ──────────────────────────────────────
        # Store ref so we can use it in pack(before=…) calls
        self._output_tf = tk.Frame(panel, bg=C["bg"])
        self._output_tf.pack(fill=tk.BOTH, expand=True)

        self._active_tab = "output"

        self._txt = tk.Text(
            self._output_tf,
            bg=C["bg"], fg=C["text"],
            font=("Consolas", 11),          # ← larger font
            insertbackground=C["text"],
            selectbackground=C["card2"],
            relief=tk.FLAT, bd=0,
            wrap=tk.WORD,
            state=tk.DISABLED,
            padx=20, pady=14,
            spacing1=2, spacing3=2,         # extra line spacing for readability
        )
        vsb = ttk.Scrollbar(self._output_tf,
                            style="Slim.Vertical.TScrollbar",
                            orient=tk.VERTICAL,
                            command=self._txt.yview)
        self._txt.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        for tag, cfg in {
            "high":   {"foreground": C["red"]},
            "med":    {"foreground": C["yellow"]},
            "low":    {"foreground": C["blue"]},
            "ok":     {"foreground": C["green"]},
            "warn":   {"foreground": C["orange"]},
            "ml":     {"foreground": C["purple"]},
            "dim":    {"foreground": C["faint"]},
            "banner": {"foreground": C["green"],
                       "font": ("Consolas", 11, "bold")},
        }.items():
            self._txt.tag_config(tag, **cfg)

        return panel

    def _draw_progress(self, score: int | None = None,
                       color: str | None = None):
        if score is None: score = self._score
        if color is None:
            color = _VERDICT_COLOR.get(self._verdict, C["faint"])
        c = self._prog
        w = c.winfo_width() or 600
        c.delete("all")
        c.create_rectangle(0, 0, w, 3, fill=C["card2"], outline="")
        fw = max(0, round(score / 100 * w))
        if fw:
            c.create_rectangle(0, 0, fw, 3, fill=color, outline="")

    # ── Tab helpers ───────────────────────────────────────────

    def _tab_btn(self, parent, label: str, cmd) -> tk.Button:
        b = tk.Button(parent, text=f"  {label}  ", command=cmd,
                      bg=C["surface"], fg=C["muted"],
                      activebackground=C["surface"],
                      activeforeground=C["text"],
                      font=("Segoe UI", 9, "bold"),
                      relief=tk.FLAT, bd=0,
                      padx=6, pady=11,
                      cursor="hand2")
        b.bind("<Enter>", lambda _: b.configure(fg=C["text"]))
        b.bind("<Leave>", lambda _: b.configure(
            fg=C["white"] if b == getattr(self, "_active_tab_btn", None)
            else C["muted"]))
        return b

    def _switch_tab(self, tab: str):
        self._active_tab = tab
        # Hide all content frames
        for f in (self._output_tf, self._history_tf, self._model_tf,
                  self._dash_tf, self._about_tf):
            f.pack_forget()
        # Hide scan-info bar when leaving the output tab
        if tab != "output":
            try:
                self._scan_info.pack_forget()
            except Exception:
                pass
        # Reset all tab button colours
        for b in (self._tab_out_btn, self._tab_hist_btn,
                  self._tab_model_btn, self._tab_dash_btn, self._tab_about_btn):
            b.configure(fg=C["muted"])

        if tab == "output":
            # Re-show scan-info bar if a scan is currently running
            if self._scanning:
                try:
                    self._scan_info.pack(fill=tk.X, before=self._output_tf)
                except Exception:
                    pass
            self._output_tf.pack(fill=tk.BOTH, expand=True)
            self._tab_out_btn.configure(fg=C["white"])
            self._active_tab_btn = self._tab_out_btn
        elif tab == "history":
            self._history_tf.pack(fill=tk.BOTH, expand=True)
            self._tab_hist_btn.configure(fg=C["white"])
            self._active_tab_btn = self._tab_hist_btn
            self._refresh_history()
        elif tab == "model":
            self._model_tf.pack(fill=tk.BOTH, expand=True)
            self._tab_model_btn.configure(fg=C["white"])
            self._active_tab_btn = self._tab_model_btn
            # after(100) gives Tk time to fully resolve geometry before we
            # populate — guarantees winfo_width() returns the real canvas width.
            self.after(100, self._force_model_refresh)
        elif tab == "dashboard":
            self._dash_tf.pack(fill=tk.BOTH, expand=True)
            self._tab_dash_btn.configure(fg=C["white"])
            self._active_tab_btn = self._tab_dash_btn
            self.after(100, self._force_dash_refresh)
        elif tab == "about":
            self._about_tf.pack(fill=tk.BOTH, expand=True)
            self._tab_about_btn.configure(fg=C["white"])
            self._active_tab_btn = self._tab_about_btn

        # Slide active-tab underline to the selected button
        self.after(5, self._move_tab_underline)

    # ── About tab ─────────────────────────────────────────────

    def _build_about_tab(self, parent):  # noqa: C901
        """Scrollable About page explaining how ShieldScan works."""

        # ── Scrollable canvas setup ───────────────────────────
        outer = tk.Frame(parent, bg=C["bg"])
        outer.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(outer, bg=C["bg"], highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(outer, style="Slim.Vertical.TScrollbar",
                            orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        pad = tk.Frame(canvas, bg=C["bg"])
        _win = canvas.create_window((0, 0), window=pad, anchor="nw")

        def _on_resize(e):
            canvas.itemconfigure(_win, width=e.width)
        canvas.bind("<Configure>", _on_resize)

        def _on_frame_configure(_e=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
        pad.bind("<Configure>", _on_frame_configure)

        canvas.bind("<Enter>",  lambda _: canvas.bind_all("<MouseWheel>",
            lambda e: canvas.yview_scroll(-1 * (e.delta // 120), "units")))
        canvas.bind("<Leave>", lambda _: canvas.unbind_all("<MouseWheel>"))

        # ── Helper: section divider ───────────────────────────
        def _section(title: str, color: str = "muted") -> tk.Frame:
            tk.Label(pad, text=title,
                     fg=C[color], bg=C["bg"],
                     font=("Segoe UI", 9, "bold"),
                     anchor="w").pack(fill=tk.X, padx=24, pady=(28, 4))
            tk.Frame(pad, bg=C["border"], height=1).pack(fill=tk.X, padx=24)
            f = tk.Frame(pad, bg=C["surface"])
            f.pack(fill=tk.X, padx=24, pady=(1, 0))
            return f

        def _card(parent_f: tk.Frame, title: str, body: str,
                  accent: str = "blue", icon: str = "") -> tk.Frame:
            card = tk.Frame(parent_f, bg=C["card"])
            card.pack(fill=tk.X, padx=0, pady=(0, 6))
            tk.Frame(card, bg=C[accent], width=4).pack(side=tk.LEFT, fill=tk.Y)
            inner = tk.Frame(card, bg=C["card"])
            inner.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=14, pady=12)
            title_row = tk.Frame(inner, bg=C["card"])
            title_row.pack(fill=tk.X)
            if icon:
                tk.Label(title_row, text=icon + "  ", fg=C[accent], bg=C["card"],
                         font=("Segoe UI", 11)).pack(side=tk.LEFT)
            tk.Label(title_row, text=title, fg=C[accent], bg=C["card"],
                     font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, anchor="w")
            tk.Label(inner, text=body, fg=C["muted"], bg=C["card"],
                     font=("Segoe UI", 8), wraplength=700,
                     justify=tk.LEFT, anchor="w").pack(fill=tk.X, pady=(4, 0))
            return card

        # ════════════════════════════════════════════════════════
        # HERO HEADER
        # ════════════════════════════════════════════════════════
        hero = tk.Frame(pad, bg=C["surface"])
        hero.pack(fill=tk.X)
        tk.Frame(hero, bg=C["green"], height=3).pack(fill=tk.X)

        hero_inner = tk.Frame(hero, bg=C["surface"])
        hero_inner.pack(fill=tk.X, padx=30, pady=22)

        title_row = tk.Frame(hero_inner, bg=C["surface"])
        title_row.pack(anchor="w")
        tk.Label(title_row, text="🛡 ", bg=C["surface"],
                 font=("Segoe UI", 28)).pack(side=tk.LEFT)
        tk.Label(title_row, text="Shield", fg=C["white"], bg=C["surface"],
                 font=("Segoe UI", 26, "bold")).pack(side=tk.LEFT)
        tk.Label(title_row, text="Scan", fg=C["green"], bg=C["surface"],
                 font=("Segoe UI", 26, "bold")).pack(side=tk.LEFT)
        tk.Label(title_row, text="  v2.0", fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 13)).pack(side=tk.LEFT, pady=(8, 0))

        tk.Label(hero_inner,
                 text="Windows Rootkit & Advanced Threat Detector",
                 fg=C["text"], bg=C["surface"],
                 font=("Segoe UI", 12)).pack(anchor="w", pady=(4, 2))
        tk.Label(hero_inner,
                 text="Detects hidden processes, stealthy network sockets, tampered drivers, "
                      "registry persistence, and file integrity violations — entirely offline.",
                 fg=C["muted"], bg=C["surface"],
                 font=("Segoe UI", 9), wraplength=820,
                 justify=tk.LEFT).pack(anchor="w")

        # Stat chips
        chips_row = tk.Frame(hero_inner, bg=C["surface"])
        chips_row.pack(anchor="w", pady=(14, 0))
        for chip_txt, chip_clr in (
            ("6 Scanner Modules", "green"),
            ("35-Feature ML Model", "blue"),
            ("MITRE ATT&CK Mapped", "purple"),
            ("100% Offline", "orange"),
            ("Zero Telemetry", "teal"),
        ):
            chip = tk.Frame(chips_row, bg=C["card2"])
            chip.pack(side=tk.LEFT, padx=(0, 8))
            tk.Label(chip, text=f"  {chip_txt}  ",
                     fg=C[chip_clr], bg=C["card2"],
                     font=("Segoe UI", 8, "bold")).pack(pady=5)

        # ════════════════════════════════════════════════════════
        # THE PROBLEM
        # ════════════════════════════════════════════════════════
        prob_f = _section("THE PROBLEM  —  Why rootkits are so hard to detect", "red")
        prob_body = tk.Frame(prob_f, bg=C["surface"])
        prob_body.pack(fill=tk.X, padx=16, pady=14)

        tk.Label(prob_body,
                 text=(
                     "A rootkit is malware that embeds itself into the operating system's "
                     "core — at the kernel level — and rewrites the very functions the OS "
                     "uses to report what is running. When Windows asks 'what processes "
                     "exist?', the rootkit intercepts the answer and removes itself from "
                     "the list. Standard antivirus tools that rely on the same OS calls "
                     "never see it.\n\n"
                     "Think of it like a CCTV camera in a bank that the robber has already "
                     "hacked — the camera keeps showing an empty corridor while the vault is "
                     "being emptied. No matter how many times you look at the feed, you see "
                     "nothing wrong."
                 ),
                 fg=C["text"], bg=C["surface"],
                 font=("Segoe UI", 9), wraplength=820,
                 justify=tk.LEFT).pack(anchor="w")

        # Rootkit intercept diagram
        diag = tk.Frame(prob_body, bg=C["card2"])
        diag.pack(fill=tk.X, pady=(14, 0))
        diag_inner = tk.Frame(diag, bg=C["card2"])
        diag_inner.pack(fill=tk.X, padx=20, pady=14)
        tk.Label(diag_inner, text="How a rootkit hides:",
                 fg=C["red"], bg=C["card2"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 8))
        for step_txt, clr in (
            ("① Your antivirus calls  NtQuerySystemInformation()  to list processes", "muted"),
            ("② Rootkit kernel hook intercepts the call BEFORE the real OS responds", "red"),
            ("③ Rootkit removes its own PID from the list", "red"),
            ("④ Antivirus receives a clean-looking process list — rootkit is invisible", "orange"),
        ):
            tk.Label(diag_inner, text=f"   {step_txt}",
                     fg=C[clr], bg=C["card2"],
                     font=("Consolas", 8)).pack(anchor="w", pady=2)

        # ════════════════════════════════════════════════════════
        # OUR APPROACH — THE SNAPSHOT TECHNIQUE
        # ════════════════════════════════════════════════════════
        snap_f = _section("OUR APPROACH  —  The Cross-View Snapshot Technique", "green")
        snap_body = tk.Frame(snap_f, bg=C["surface"])
        snap_body.pack(fill=tk.X, padx=16, pady=14)

        tk.Label(snap_body,
                 text=(
                     "ShieldScan's core idea: a rootkit can control one information source, "
                     "but it is almost impossible to simultaneously intercept multiple "
                     "completely independent OS paths at the same moment.\n\n"
                     "At the start of each scan, ShieldScan takes an instantaneous "
                     "snapshot of the system state from several independent APIs "
                     "simultaneously — like photographing the same scene from three "
                     "different cameras at the exact same moment. If any camera shows "
                     "something the others do not, there is something hiding."
                 ),
                 fg=C["text"], bg=C["surface"],
                 font=("Segoe UI", 9), wraplength=820,
                 justify=tk.LEFT).pack(anchor="w")

        # Cross-view diagram
        cv_diag = tk.Frame(snap_body, bg=C["card2"])
        cv_diag.pack(fill=tk.X, pady=(14, 0))
        cv_inner = tk.Frame(cv_diag, bg=C["card2"])
        cv_inner.pack(fill=tk.X, padx=20, pady=14)
        tk.Label(cv_inner,
                 text="Cross-view comparison (Process scanner example):",
                 fg=C["green"], bg=C["card2"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 8))

        cols = tk.Frame(cv_inner, bg=C["card2"])
        cols.pack(fill=tk.X)
        for src, pids, clr in (
            ("psutil\n(NtQuerySystemInfo)", "PID 1044\nPID 1188\nPID 2304\nPID 4412", "blue"),
            ("WMIC\n(WMI subsystem)",       "PID 1044\nPID 1188  ←\nPID 2304\nPID 4412", "orange"),
            ("tasklist\n(Win32 API)",        "PID 1044\nPID 1188  ←\nPID 2304\nPID 4412", "purple"),
        ):
            col = tk.Frame(cols, bg=C["card"])
            col.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 8))
            tk.Label(col, text=src, fg=C[clr], bg=C["card"],
                     font=("Segoe UI", 8, "bold")).pack(pady=(8, 4))
            tk.Frame(col, bg=C["border"], height=1).pack(fill=tk.X)
            tk.Label(col, text=pids, fg=C["text"], bg=C["card"],
                     font=("Consolas", 9), justify=tk.LEFT).pack(anchor="w", padx=10, pady=8)

        tk.Label(cv_inner,
                 text="PID 1188 appears in WMIC and tasklist but NOT in psutil  →  "
                      "flagged as hidden process (rootkit indicator)",
                 fg=C["yellow"], bg=C["card2"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(10, 2))

        # ════════════════════════════════════════════════════════
        # HOW A SCAN WORKS — STEP BY STEP FLOW
        # ════════════════════════════════════════════════════════
        flow_f = _section("HOW A SCAN WORKS  —  Step-by-step flow", "blue")
        flow_body = tk.Frame(flow_f, bg=C["surface"])
        flow_body.pack(fill=tk.X, padx=16, pady=14)

        steps = [
            ("①", "Freeze & Snapshot",
             "All six scanner modules query the system simultaneously. "
             "Processes, network sockets, kernel drivers, registry keys, "
             "scheduled tasks and file hashes are all captured at the same instant "
             "to prevent a rootkit from 'moving out of the way' between queries.",
             "green"),
            ("②", "Cross-View Comparison",
             "Each module compares its two or three independent data sources. "
             "A process visible in WMIC but absent from psutil, a TCP port seen "
             "by netstat but invisible to psutil, or a driver in the registry "
             "but missing from driverquery — each discrepancy is a potential "
             "hiding artefact and becomes a finding.",
             "blue"),
            ("③", "Heuristic Analysis",
             "Beyond cross-view gaps, each finding is checked against known bad "
             "patterns: system processes running from the wrong directory "
             "(svchost.exe outside System32), executables dropped in temp folders, "
             "autorun registry keys pointing to unusual paths, unsigned drivers, "
             "and ports matching known command-and-control frameworks.",
             "orange"),
            ("④", "RAG False-Positive Filter",
             "Findings are passed through a local Retrieval-Augmented Generation "
             "filter backed by a curated knowledge base of known-benign behaviours "
             "(e.g. Razer Synapse using port 1337, OneDrive using dynamic ports). "
             "This suppresses or downgrades confirmed false positives before they "
             "reach the user — entirely offline, no data ever leaves this machine.",
             "teal"),
            ("⑤", "ML Classification",
             "Each surviving finding is converted into a 35-dimensional numeric "
             "feature vector (port numbers, keyword flags, severity, scan type, "
             "path characteristics, etc.) and fed to a trained Random Forest "
             "classifier. The model assigns a threat category — Kernel Rootkit, "
             "Process Injection, C2 Backdoor, Registry Persistence, etc. — and a "
             "confidence score from 0 to 1.",
             "purple"),
            ("⑥", "MITRE ATT&CK Mapping",
             "Every classified finding is automatically mapped to relevant MITRE "
             "ATT&CK technique IDs (e.g. T1055 Process Injection, T1547 Boot "
             "Autostart Execution). This links each alert to the wider threat "
             "intelligence framework used by security teams worldwide.",
             "pink"),
            ("⑦", "Report & Remediation",
             "Results are displayed with severity (HIGH / MED / LOW), the raw "
             "finding reason, the ML category and confidence, MITRE IDs, and "
             "step-by-step remediation guidance. The full report can be exported "
             "to CSV. Scan metadata is saved locally for historical comparison.",
             "green"),
        ]

        for icon, title, body_txt, clr in steps:
            step_card = tk.Frame(flow_body, bg=C["card"])
            step_card.pack(fill=tk.X, pady=(0, 6))
            tk.Frame(step_card, bg=C[clr], width=4).pack(side=tk.LEFT, fill=tk.Y)
            s_inner = tk.Frame(step_card, bg=C["card"])
            s_inner.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=14, pady=10)
            hdr_row = tk.Frame(s_inner, bg=C["card"])
            hdr_row.pack(fill=tk.X)
            tk.Label(hdr_row, text=icon + "  ", fg=C[clr], bg=C["card"],
                     font=("Segoe UI", 13)).pack(side=tk.LEFT)
            tk.Label(hdr_row, text=title, fg=C[clr], bg=C["card"],
                     font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, anchor="w")
            tk.Label(s_inner, text=body_txt, fg=C["muted"], bg=C["card"],
                     font=("Segoe UI", 8), wraplength=720,
                     justify=tk.LEFT, anchor="w").pack(fill=tk.X, pady=(4, 0))

        # ════════════════════════════════════════════════════════
        # DETECTION MODULES
        # ════════════════════════════════════════════════════════
        mod_f = _section("DETECTION MODULES", "orange")
        mod_body = tk.Frame(mod_f, bg=C["surface"])
        mod_body.pack(fill=tk.X, padx=16, pady=14)

        modules = [
            ("Process Analyser", "green", "🔍",
             "Compares three independent process lists — psutil "
             "(NtQuerySystemInformation), WMIC (Windows Management "
             "Instrumentation), and tasklist (Win32 CreateToolhelp32Snapshot). "
             "A PID visible in WMIC or tasklist but absent from psutil indicates "
             "the process is actively hiding from user-mode enumeration — a "
             "classic kernel rootkit signature. An ephemeral process filter "
             "(double-confirmation pass with a short delay) prevents false "
             "positives from short-lived system processes."),
            ("Rootkit Heuristics", "red", "⚠",
             "Inspects every running process for masquerading: known Windows "
             "system binaries (svchost.exe, lsass.exe, csrss.exe …) are checked "
             "against their expected paths — a svchost.exe running from "
             "C:\\Users\\Temp\\ is flagged immediately. Also checks for processes "
             "with suspicious keywords in their name, bad parent-process "
             "relationships, and executables launched from user-writable temp "
             "directories."),
            ("Network Scanner", "blue", "🌐",
             "Cross-compares TCP LISTEN ports from psutil against netstat -ano "
             "(which uses a separate kernel code path). A port open in one source "
             "but invisible in the other suggests socket-level hiding. Also checks "
             "all active connections against a list of ports associated with known "
             "malware and C2 frameworks (Metasploit: 4444, Cobalt Strike: 443/80 "
             "custom, Tor: 9050/9150, IRC backdoors: 6667/6697 …) while "
             "whitelisting legitimate software that happens to use those ports."),
            ("Kernel Driver Scanner", "purple", "🔧",
             "Compares drivers reported by the Service Control Manager "
             "(driverquery) against drivers listed in the Windows registry under "
             "HKLM\\SYSTEM\\CurrentControlSet\\Services. A driver present in the "
             "registry but absent from driverquery is potentially a hidden rootkit "
             "driver. Also flags drivers loaded from unusual paths, drivers with "
             "no description, and drivers with suspicious names."),
            ("Registry & Persistence Scanner", "orange", "🗝",
             "Scans all standard autorun locations: HKCU\\Run, HKLM\\Run, "
             "RunOnce, Winlogon Shell/Userinit, BootExecute, Image File Execution "
             "Options (IFEO debugger hijack), Scheduled Tasks, WMI event "
             "subscriptions, AppInit_DLLs, LSA authentication packages, and "
             "startup folder executables. Flags entries pointing to temp "
             "directories, unsigned executables, and known malware patterns."),
            ("File Integrity Monitor", "teal", "🔒",
             "Computes SHA-256 hashes of critical Windows system files at baseline "
             "time — ntoskrnl.exe, hal.dll, ntdll.dll, kernel32.dll, lsass.exe, "
             "winlogon.exe, services.exe and more. On each subsequent scan the "
             "hashes are recomputed and compared. Any modification — even a single "
             "byte — is flagged. Rootkits and bootkits frequently patch ntdll.dll "
             "in memory or on disk to intercept system calls."),
        ]

        for name, clr, icon, desc in modules:
            _card(mod_body, name, desc, accent=clr, icon=icon)

        # ════════════════════════════════════════════════════════
        # ML MODEL
        # ════════════════════════════════════════════════════════
        ml_f = _section("MACHINE LEARNING CLASSIFIER", "purple")
        ml_body = tk.Frame(ml_f, bg=C["surface"])
        ml_body.pack(fill=tk.X, padx=16, pady=14)

        tk.Label(ml_body,
                 text=(
                     "Every finding that passes the RAG filter is fed to a trained "
                     "Random Forest classifier. The model converts the finding into a "
                     "35-dimensional numeric feature vector capturing: the scanner module "
                     "that raised it, severity level, port number and type, process name "
                     "characteristics, 27 keyword flags extracted from the finding's "
                     "reason text (hidden, injected, hook, masquerade, temp path, "
                     "unsigned, C2 port, autorun key, etc.).\n\n"
                     "The classifier was benchmarked against a full stacking ensemble "
                     "(Random Forest + Extra Trees + Gradient Boosting + XGBoost with "
                     "a Logistic Regression meta-learner). On the 180-sample, 16-class "
                     "training set, Random Forest alone scored 93.9% accuracy and 0.947 "
                     "F1-Macro — outperforming the ensemble (87.2% / 0.884). This is "
                     "expected: stacking adds meta-learner noise when the dataset is small "
                     "relative to the number of classes."
                 ),
                 fg=C["text"], bg=C["surface"],
                 font=("Segoe UI", 9), wraplength=820,
                 justify=tk.LEFT).pack(anchor="w")

        ml_stats = tk.Frame(ml_body, bg=C["card2"])
        ml_stats.pack(fill=tk.X, pady=(14, 0))
        ms_inner = tk.Frame(ml_stats, bg=C["card2"])
        ms_inner.pack(fill=tk.X, padx=20, pady=14)
        tk.Label(ms_inner, text="Classifier snapshot:",
                 fg=C["purple"], bg=C["card2"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 6))
        for stat_k, stat_v, stat_c in (
            ("Algorithm",        "Random Forest (500 trees, balanced class weights)", "green"),
            ("Feature vector",   "35-dimensional  —  port, severity, keywords, path, scan type", "blue"),
            ("Training data",    "180 curated samples  ·  16 threat categories", "blue"),
            ("CV Accuracy",      "93.9%  (5-fold stratified cross-validation)", "green"),
            ("F1 Macro",         "0.947  (unweighted mean across all 16 classes)", "green"),
            ("Threat categories","Kernel Rootkit · Process Injection · C2 Backdoor · Registry "
                                 "Persistence · SSDT Hook · Memory Injection · Unsigned Driver "
                                 "· Hidden Socket · FIM Violation · BENIGN · …", "muted"),
        ):
            row = tk.Frame(ms_inner, bg=C["card2"])
            row.pack(fill=tk.X, pady=1)
            tk.Label(row, text=f"  {stat_k:<20}", fg=C["faint"], bg=C["card2"],
                     font=("Consolas", 8)).pack(side=tk.LEFT)
            tk.Label(row, text=stat_v, fg=C[stat_c], bg=C["card2"],
                     font=("Consolas", 8)).pack(side=tk.LEFT)

        # ════════════════════════════════════════════════════════
        # PRIVACY GUARANTEE
        # ════════════════════════════════════════════════════════
        priv_f = _section("PRIVACY & SECURITY GUARANTEE", "teal")
        priv_body = tk.Frame(priv_f, bg=C["surface"])
        priv_body.pack(fill=tk.X, padx=16, pady=14)

        for priv_icon, priv_title, priv_desc in (
            ("🔒", "100% Offline",
             "ShieldScan never opens a network socket of its own. No scan results, "
             "process names, file paths, or any system data ever leave your machine."),
            ("🗄", "Local Storage Only",
             "All data — scan logs, ML model, knowledge base, user accounts — is "
             "stored in the application folder on your local disk. Nothing is "
             "uploaded to any server or cloud."),
            ("📵", "No Telemetry",
             "There is no analytics, crash reporting, or usage tracking of any kind. "
             "The only external library used for the RAG filter is Python's own "
             "difflib (standard library)."),
            ("🔑", "Local Authentication",
             "User accounts are stored in a local users.json file using SHA-256 "
             "password hashing. There is no central account server."),
        ):
            p_row = tk.Frame(priv_body, bg=C["surface"])
            p_row.pack(fill=tk.X, pady=(0, 8))
            tk.Label(p_row, text=priv_icon + "  ", fg=C["teal"], bg=C["surface"],
                     font=("Segoe UI", 13)).pack(side=tk.LEFT, anchor="n", pady=2)
            p_text = tk.Frame(p_row, bg=C["surface"])
            p_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
            tk.Label(p_text, text=priv_title, fg=C["teal"], bg=C["surface"],
                     font=("Segoe UI", 9, "bold"), anchor="w").pack(anchor="w")
            tk.Label(p_text, text=priv_desc, fg=C["muted"], bg=C["surface"],
                     font=("Segoe UI", 8), wraplength=760,
                     justify=tk.LEFT, anchor="w").pack(anchor="w", pady=(2, 0))

        # ════════════════════════════════════════════════════════
        # FOOTER
        # ════════════════════════════════════════════════════════
        tk.Frame(pad, bg=C["border"], height=1).pack(fill=tk.X, padx=24, pady=(28, 0))
        foot = tk.Frame(pad, bg=C["bg"])
        foot.pack(fill=tk.X, padx=24, pady=(10, 24))
        tk.Label(foot,
                 text="ShieldScan v2.0  —  Built for Windows 10/11  —  Python 3.10+  —  All data stays on this device",
                 fg=C["faint"], bg=C["bg"],
                 font=("Segoe UI", 7)).pack(side=tk.LEFT)

    # ── History panel ─────────────────────────────────────────

    def _build_history_frame(self, parent):
        """Build the scrollable history list (populated on demand)."""
        # ── Header ────────────────────────────────────────────
        hrow = tk.Frame(parent, bg=C["surface"])
        hrow.pack(fill=tk.X)
        tk.Frame(hrow, bg=C["border"], height=1).pack(side=tk.BOTTOM, fill=tk.X)

        title_f = tk.Frame(hrow, bg=C["surface"])
        title_f.pack(side=tk.LEFT, padx=20, pady=12)
        tk.Label(title_f, text="Scan History",
                 fg=C["white"], bg=C["surface"],
                 font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        self._hist_count_lbl = tk.Label(title_f, text="",
                                         fg=C["faint"], bg=C["surface"],
                                         font=("Segoe UI", 8))
        self._hist_count_lbl.pack(side=tk.LEFT, padx=(8, 0), pady=(1, 0))

        btn_f = tk.Frame(hrow, bg=C["surface"])
        btn_f.pack(side=tk.RIGHT, padx=12, pady=8)

        # Compare button (enabled when 2 reports are checked)
        self._cmp_btn = tk.Button(btn_f, text="⇄  Compare",
                                   command=self._compare_selected,
                                   bg=C["card"], fg=C["faint"],
                                   activebackground=C["card2"],
                                   activeforeground=C["white"],
                                   font=("Segoe UI", 8),
                                   relief=tk.FLAT, bd=0, padx=10, pady=4,
                                   state=tk.DISABLED, cursor="hand2")
        self._cmp_btn.pack(side=tk.LEFT, padx=(0, 6))
        Tooltip(self._cmp_btn, "Select exactly 2 reports below, then compare side-by-side.")
        # Track selected reports {path: BooleanVar}
        self._hist_selected: dict[str, tk.BooleanVar] = {}

        email_all = tk.Button(btn_f, text="✉  Email Latest",
                              command=self._send_report_email,
                              bg=C["card"], fg=C["blue"],
                              activebackground=C["card2"],
                              activeforeground=C["white"],
                              font=("Segoe UI", 8),
                              relief=tk.FLAT, bd=0, padx=10, pady=4,
                              cursor="hand2")
        email_all.pack(side=tk.LEFT, padx=(0, 6))
        email_all.bind("<Enter>", lambda _: email_all.configure(
            bg=C["card2"], fg=C["white"]))
        email_all.bind("<Leave>", lambda _: email_all.configure(
            bg=C["card"], fg=C["blue"]))
        Tooltip(email_all, "Email the most recent scan report.")

        ref_btn = tk.Button(btn_f, text="↻  Refresh",
                            command=self._refresh_history,
                            bg=C["surface"], fg=C["faint"],
                            activebackground=C["card"],
                            activeforeground=C["text"],
                            font=("Segoe UI", 8),
                            relief=tk.FLAT, bd=0, padx=10, pady=4,
                            cursor="hand2")
        ref_btn.pack(side=tk.LEFT)
        ref_btn.bind("<Enter>", lambda _: ref_btn.configure(
            fg=C["text"], bg=C["card"]))
        ref_btn.bind("<Leave>", lambda _: ref_btn.configure(
            fg=C["faint"], bg=C["surface"]))

        # ── Column headers ────────────────────────────────────
        col_hdr = tk.Frame(parent, bg=C["card"], height=28)
        col_hdr.pack(fill=tk.X)
        col_hdr.pack_propagate(False)
        tk.Frame(col_hdr, bg=C["border"], height=1).pack(
            side=tk.BOTTOM, fill=tk.X)
        for txt, anch, pad_l in (
            ("DATE & TIME",  "w", 24),
            ("VERDICT",      "w",  0),
            ("RISK",         "e",  0),
            ("ACTIONS",      "e", 12),
        ):
            tk.Label(col_hdr, text=txt, fg=C["faint"], bg=C["card"],
                     font=("Segoe UI", 7, "bold"),
                     anchor=anch, padx=pad_l).pack(
                         side=tk.LEFT if anch == "w" else tk.RIGHT,
                         expand=(anch == "w"))

        # ── Scrollable list ───────────────────────────────────
        canvas = tk.Canvas(parent, bg=C["bg"], highlightthickness=0, bd=0)
        vsb    = ttk.Scrollbar(parent, style="Slim.Vertical.TScrollbar",
                               orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._hist_canvas = canvas
        self._hist_inner  = tk.Frame(canvas, bg=C["bg"])
        self._hist_win    = canvas.create_window(
            (0, 0), window=self._hist_inner, anchor="nw")

        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfig(self._hist_win, width=e.width))
        self._hist_inner.bind("<Configure>",
                              lambda e: canvas.configure(
                                  scrollregion=canvas.bbox("all")))
        def _hist_wheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind("<Enter>",
                    lambda _: canvas.bind_all("<MouseWheel>", _hist_wheel))
        canvas.bind("<Leave>",
                    lambda _: canvas.unbind_all("<MouseWheel>"))

    def _refresh_history(self):
        """Reload the list of past HTML reports filtered to current user."""
        for w in self._hist_inner.winfo_children():
            w.destroy()
        self._hist_selected.clear()
        try:
            self._cmp_btn.configure(state=tk.DISABLED, fg=C["faint"])
        except Exception:
            pass

        meta = _load_scan_meta()

        all_reports = sorted(
            glob.glob(os.path.join(_LOGS, "report_*.html")),
            key=os.path.getmtime, reverse=True,
        )

        # Filter: only show reports tagged to the current user
        reports = []
        for p in all_reports:
            fn = os.path.basename(p)
            entry = meta.get(fn, {})
            if entry.get("user") == self._current_user:
                reports.append(p)

        if not reports:
            empty_f = tk.Frame(self._hist_inner, bg=C["bg"])
            empty_f.pack(fill=tk.BOTH, expand=True, pady=60)
            tk.Label(empty_f, text="📋",
                     bg=C["bg"], font=("Segoe UI", 32)).pack()
            tk.Label(empty_f, text="No scan reports yet",
                     fg=C["text"], bg=C["bg"],
                     font=("Segoe UI", 11, "bold")).pack(pady=(8, 4))
            tk.Label(empty_f,
                     text=f"No scans found for '{self._current_user}'.\n"
                          "Run a scan to generate your first report.",
                     fg=C["muted"], bg=C["bg"],
                     font=("Segoe UI", 9), justify=tk.CENTER).pack()
            self._hist_count_lbl.configure(text="")
            return

        n = len(reports)
        self._hist_count_lbl.configure(
            text=f"  {n} report{'s' if n != 1 else ''}")
        for path in reports:
            self._hist_row(self._hist_inner, path)

    def _hist_row(self, parent, path: str):
        """One card-row in the history list for a given report file."""
        fname = os.path.basename(path)

        # ── Parse filename ────────────────────────────────────
        try:
            ts_part  = fname.replace("report_", "").replace(".html", "")
            dt       = datetime.strptime(ts_part, "%Y%m%d_%H%M%S")
            date_str = dt.strftime("%d %b %Y")
            time_str = dt.strftime("%H:%M")
        except Exception:
            date_str = fname
            time_str = ""

        # ── Parse report HTML ─────────────────────────────────
        risk_score  = 0
        verdict_txt = ""
        summary_txt = ""
        vclr        = C["faint"]
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                snippet = f.read(6000)
            ms = re.search(r'class="risk-score"[^>]*>(\d+)', snippet)
            if ms:
                risk_score = int(ms.group(1))
            mv = re.search(r'<div class="verdict">(.*?)</div>', snippet, re.S)
            if mv:
                raw = re.sub(r"<[^>]+>", "", mv.group(1)).strip()
                raw = re.sub(r"\s+", " ", raw)
                for kw in ("COMPROMISED", "SUSPICIOUS", "LOW RISK", "CLEAN"):
                    if kw in raw.upper():
                        verdict_txt = kw
                        break
                m2 = re.search(r"(\d+)\s+finding", raw, re.I)
                if m2:
                    cnt = int(m2.group(1))
                    summary_txt = (f"{cnt} finding{'s' if cnt != 1 else ''} detected"
                                   if cnt else "No threats found")
                else:
                    summary_txt = raw[:60] if raw else ""
            vclr = _VERDICT_COLOR.get(verdict_txt, C["faint"])
        except Exception:
            pass

        def _open(p=path):
            webbrowser.open("file:///" + p.replace("\\", "/"))

        def _email(p=path):
            self._send_report_email(report_path=p)

        # ── Build card — track every surface-bg widget for hover ──
        # _h = list of all widgets whose bg flips surface↔card on row hover.
        # Widgets with a fixed colour (accent bar, verdict pill, risk fill,
        # the "Open" button) are intentionally excluded.
        _h: list = []

        def _sf(cls, par, **kw):
            """Create widget; auto-enroll in hover group when bg=surface."""
            w = cls(par, **kw)
            if kw.get("bg") == C["surface"]:
                _h.append(w)
            return w

        card = _sf(tk.Frame, parent, bg=C["surface"])
        card.pack(fill=tk.X, pady=1)
        tk.Frame(card, bg=C["border"], height=1).pack(side=tk.BOTTOM, fill=tk.X)

        # Left verdict accent bar — fixed colour, NOT in hover group
        tk.Frame(card, width=3, bg=vclr).pack(side=tk.LEFT, fill=tk.Y)

        # Compare checkbox
        sel_var = tk.BooleanVar(value=False)
        self._hist_selected[path] = sel_var

        def _update_cmp(*_):
            count = sum(1 for v in self._hist_selected.values() if v.get())
            if count == 2:
                self._cmp_btn.configure(state=tk.NORMAL, fg=C["blue"])
            else:
                self._cmp_btn.configure(state=tk.DISABLED, fg=C["faint"])

        chk_lbl = tk.Label(card, text="  ", width=2,
                            bg=C["card"], font=("Consolas", 8),
                            cursor="hand2")
        chk_lbl.pack(side=tk.LEFT, padx=(6, 0), pady=16)

        def _toggle_sel(*_):
            sel_var.set(not sel_var.get())
        for w in (chk_lbl,):
            w.bind("<Button-1>", _toggle_sel)

        def _ref_chk(*_):
            if sel_var.get():
                chk_lbl.configure(bg=C["green"], text="✓", fg=C["bg"])
            else:
                chk_lbl.configure(bg=C["card"], text="  ", fg=C["card"])
            _update_cmp()
        sel_var.trace_add("write", _ref_chk)
        Tooltip(chk_lbl, "Select for comparison (need exactly 2).")

        body = _sf(tk.Frame, card, bg=C["surface"])
        body.pack(side=tk.LEFT, fill=tk.BOTH, expand=True,
                  padx=(16, 12), pady=12)

        # ── Row 1: date/time + verdict pill ───────────────────
        row1 = _sf(tk.Frame, body, bg=C["surface"])
        row1.pack(fill=tk.X)

        dt_f = _sf(tk.Frame, row1, bg=C["surface"])
        dt_f.pack(side=tk.LEFT)
        _sf(tk.Label, dt_f, text=date_str,
            fg=C["white"], bg=C["surface"],
            font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        _sf(tk.Label, dt_f, text=f"  {time_str}",
            fg=C["faint"], bg=C["surface"],
            font=("Segoe UI", 9)).pack(side=tk.LEFT)

        if verdict_txt:
            # Pill has a fixed colour — NOT in hover group
            pill_bg = vclr if vclr != C["faint"] else C["card2"]
            pill_fg = C["bg"] if vclr != C["faint"] else C["muted"]
            tk.Label(row1, text=f"  {verdict_txt}  ",
                     fg=pill_fg, bg=pill_bg,
                     font=("Segoe UI", 7, "bold"), padx=2).pack(side=tk.RIGHT)

        # ── Row 2: mini risk bar ──────────────────────────────
        bar_f = _sf(tk.Frame, body, bg=C["surface"])
        bar_f.pack(fill=tk.X, pady=(6, 0))
        _sf(tk.Label, bar_f, text="Risk",
            fg=C["faint"], bg=C["surface"],
            font=("Segoe UI", 7)).pack(side=tk.LEFT)
        # bar_bg stays card2 — fixed, not in hover group
        bar_bg = tk.Frame(bar_f, bg=C["card2"], height=6)
        bar_bg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 8))
        if risk_score > 0:
            tk.Frame(bar_bg, bg=vclr, height=6).place(
                relwidth=min(risk_score / 100, 1.0), relheight=1.0)
        score_fg = vclr if vclr != C["faint"] else C["muted"]
        _sf(tk.Label, bar_f, text=f"{risk_score}/100",
            fg=score_fg, bg=C["surface"],
            font=("Consolas", 8, "bold")).pack(side=tk.RIGHT)

        # ── Row 3: summary text ───────────────────────────────
        if summary_txt:
            _sf(tk.Label, body, text=summary_txt,
                fg=C["muted"], bg=C["surface"],
                font=("Segoe UI", 8), anchor="w").pack(fill=tk.X, pady=(4, 0))

        # ── Row 4: action buttons ─────────────────────────────
        act_f = _sf(tk.Frame, body, bg=C["surface"])
        act_f.pack(fill=tk.X, pady=(6, 0))

        # "Open Report" button: fixed bg=card, not in hover group
        open_btn = tk.Button(act_f, text="▶  Open Report",
                             command=_open,
                             bg=C["card"], fg=C["blue"],
                             activebackground=C["card2"],
                             activeforeground=C["white"],
                             font=("Segoe UI", 8),
                             relief=tk.FLAT, bd=0,
                             padx=10, pady=3, cursor="hand2")
        open_btn.pack(side=tk.LEFT, padx=(0, 8))
        open_btn.bind("<Enter>", lambda _: open_btn.configure(
            bg=C["card2"], fg=C["white"]))
        open_btn.bind("<Leave>", lambda _: open_btn.configure(
            bg=C["card"], fg=C["blue"]))

        # "Email" button: also fixed bg=card
        email_btn = tk.Button(act_f, text="✉  Email",
                              command=_email,
                              bg=C["card"], fg=C["muted"],
                              activebackground=C["card2"],
                              activeforeground=C["text"],
                              font=("Segoe UI", 8),
                              relief=tk.FLAT, bd=0,
                              padx=8, pady=3, cursor="hand2")
        email_btn.pack(side=tk.LEFT)
        email_btn.bind("<Enter>", lambda _: email_btn.configure(
            fg=C["text"], bg=C["card2"]))
        email_btn.bind("<Leave>", lambda _: email_btn.configure(
            fg=C["muted"], bg=C["card"]))
        Tooltip(email_btn, "Send this report by email.")

        # ── Hover: flip every surface-bg widget to card and back ──
        def _on_enter(_=None):
            for w in _h:
                try: w.configure(bg=C["card"])
                except Exception: pass

        def _on_leave(_=None):
            for w in _h:
                try: w.configure(bg=C["surface"])
                except Exception: pass

        for w in _h:
            w.bind("<Enter>", _on_enter)
            w.bind("<Leave>", _on_leave)

    # ══════════════════════════════════════════════════════════
    # Model Info panel
    # ══════════════════════════════════════════════════════════

    def _move_tab_underline(self):
        """Slide the green underline bar beneath the currently active tab button."""
        try:
            btn = self._active_tab_btn
            if btn is None:
                return
            self.update_idletasks()
            x = btn.winfo_x()
            w = btn.winfo_width()
            h = btn.winfo_height()
            self._tab_bar.place(x=x, y=h - 2, width=w, height=2)
            self._tab_bar.lift()
        except Exception:
            pass

    def _force_model_refresh(self):
        """Set canvas window width explicitly then populate. Called via after(100)."""
        try:
            self._model_canvas.update_idletasks()
            w = self._model_canvas.winfo_width()
            if w > 1:
                self._model_canvas.itemconfig(self._model_wid, width=w)
            self._refresh_model_info()
            # Re-apply scrollregion after content is laid out
            self._model_inner.update_idletasks()
            self._model_canvas.configure(
                scrollregion=self._model_canvas.bbox("all"))
        except Exception:
            self._refresh_model_info()

    def _force_dash_refresh(self):
        """Set canvas window width explicitly then populate. Called via after(100)."""
        try:
            self._dash_canvas.update_idletasks()
            w = self._dash_canvas.winfo_width()
            if w > 1:
                self._dash_canvas.itemconfig(self._dash_wid, width=w)
            self._refresh_dashboard()
            self._dash_inner.update_idletasks()
            self._dash_canvas.configure(
                scrollregion=self._dash_canvas.bbox("all"))
        except Exception:
            self._refresh_dashboard()

    def _build_model_frame(self, parent):
        """Build the static scaffold for the Model Info tab."""
        hrow = tk.Frame(parent, bg=C["surface"])
        hrow.pack(fill=tk.X)
        tk.Frame(hrow, bg=C["border"], height=1).pack(side=tk.BOTTOM, fill=tk.X)
        tk.Label(hrow, text="ML Model Information",
                 fg=C["white"], bg=C["surface"],
                 font=("Segoe UI", 10, "bold"),
                 padx=20, pady=12).pack(side=tk.LEFT)
        ref_btn = tk.Button(hrow, text="↻  Refresh",
                            command=self._refresh_model_info,
                            bg=C["surface"], fg=C["faint"],
                            activebackground=C["card"],
                            activeforeground=C["text"],
                            font=("Segoe UI", 8),
                            relief=tk.FLAT, bd=0, padx=10, pady=4,
                            cursor="hand2")
        ref_btn.pack(side=tk.RIGHT, padx=12, pady=8)
        ref_btn.bind("<Enter>", lambda _: ref_btn.configure(fg=C["text"], bg=C["card"]))
        ref_btn.bind("<Leave>", lambda _: ref_btn.configure(fg=C["faint"], bg=C["surface"]))

        # Scrollable body
        canvas = tk.Canvas(parent, bg=C["bg"], highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(parent, style="Slim.Vertical.TScrollbar",
                            orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._model_inner = tk.Frame(canvas, bg=C["bg"])
        _wid = canvas.create_window((0, 0), window=self._model_inner, anchor="nw")

        # Store refs so _switch_tab can force the correct width before populating
        self._model_canvas = canvas
        self._model_wid    = _wid

        def _on_canvas_cfg(e, _c=canvas, _w=_wid):
            _c.itemconfig(_w, width=e.width)
        canvas.bind("<Configure>", _on_canvas_cfg)

        def _on_inner_cfg(e, _c=canvas):
            _c.configure(scrollregion=_c.bbox("all"))
        self._model_inner.bind("<Configure>", _on_inner_cfg)

        def _mw(e): canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        canvas.bind("<Enter>", lambda _: canvas.bind_all("<MouseWheel>", _mw))
        canvas.bind("<Leave>", lambda _: canvas.unbind_all("<MouseWheel>"))

    def _recompute_oof_metrics(self):
        """
        Background thread: load existing model, run 5-fold cross_val_predict
        on the built-in SAMPLES, compute f1/precision/recall, patch model_meta.json.
        Does NOT retrain — uses the already-saved pipeline.
        """
        self._show_toast("Recomputing OOF metrics — approx 30 s…", "info")

        def _work():
            try:
                import numpy as np
                import tempfile
                from sklearn.model_selection import StratifiedKFold, cross_val_predict
                from sklearn.metrics import f1_score, precision_score, recall_score
                from sklearn.preprocessing import LabelEncoder
                from ml_model.threat_model import get_classifier, extract_features
                from ml_model.model_data import SAMPLES

                clf = get_classifier()
                if not clf._ready:
                    self.after(0, lambda: self._show_toast(
                        "Model not loaded — run a scan first.", "warn"))
                    return

                X = np.array([
                    extract_features(
                        {"reason": r, "severity": sev, "port": port, "name": name},
                        scan_type,
                    )
                    for r, scan_type, sev, port, name, _label in SAMPLES
                ])
                raw_labels = [s[5] for s in SAMPLES]
                le = LabelEncoder()
                le.fit(clf.label_names)
                y = le.transform(raw_labels)

                cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
                y_oof = cross_val_predict(clf.pipeline, X, y, cv=cv)

                f1_mac  = float(f1_score(y, y_oof, average="macro",    zero_division=0))
                f1_wt   = float(f1_score(y, y_oof, average="weighted", zero_division=0))
                prec    = float(precision_score(y, y_oof, average="macro", zero_division=0))
                rec     = float(recall_score(y, y_oof, average="macro",   zero_division=0))

                meta2: dict = {}
                if os.path.exists(_MODEL_META):
                    with open(_MODEL_META, encoding="utf-8") as mf:
                        meta2 = json.load(mf)
                meta2["f1_macro"]        = f1_mac
                meta2["f1_weighted"]     = f1_wt
                meta2["precision_macro"] = prec
                meta2["recall_macro"]    = rec

                _dir = os.path.dirname(_MODEL_META)
                with tempfile.NamedTemporaryFile(
                        "w", dir=_dir, delete=False,
                        suffix=".tmp", encoding="utf-8") as tf:
                    json.dump(meta2, tf, indent=2)
                    _tmp = tf.name
                os.replace(_tmp, _MODEL_META)

                self.after(0, self._force_model_refresh)
                self.after(0, lambda: self._show_toast(
                    f"Metrics recomputed  ✓  F1={f1_mac:.3f}  Prec={prec:.3f}  Rec={rec:.3f}",
                    "ok"))
            except Exception as _exc:
                self.after(0, lambda: self._show_toast(
                    f"Recompute failed: {_exc}", "warn"))

        import threading
        threading.Thread(target=_work, daemon=True).start()

    def _refresh_model_info(self):  # noqa: C901  (long but single logical unit)
        for w in self._model_inner.winfo_children():
            w.destroy()

        meta: dict = {}
        if os.path.exists(_MODEL_META):
            try:
                with open(_MODEL_META, encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                pass

        pad = tk.Frame(self._model_inner, bg=C["bg"])
        pad.pack(fill=tk.X, padx=28, pady=20)

        # ── Shared helpers ────────────────────────────────────

        def _section(title: str) -> tk.Frame:
            tk.Label(pad, text=title, fg=C["muted"], bg=C["bg"],
                     font=("Segoe UI", 9, "bold"), anchor="w").pack(
                         fill=tk.X, pady=(22, 6))
            tk.Frame(pad, bg=C["border"], height=1).pack(fill=tk.X)
            f = tk.Frame(pad, bg=C["surface"])
            f.pack(fill=tk.X, pady=(1, 0))
            return f

        def _kv(parent, key: str, val: str, val_color: str = "text"):
            row = tk.Frame(parent, bg=C["surface"])
            row.pack(fill=tk.X, padx=16, pady=5)
            tk.Label(row, text=key, fg=C["faint"], bg=C["surface"],
                     font=("Segoe UI", 8), width=26, anchor="w").pack(side=tk.LEFT)
            tk.Label(row, text=val, fg=C[val_color], bg=C["surface"],
                     font=("Segoe UI", 9, "bold"), anchor="e").pack(side=tk.RIGHT)

        def _bar_row(parent, key: str, val: float, color: str = "blue"):
            row = tk.Frame(parent, bg=C["surface"])
            row.pack(fill=tk.X, padx=16, pady=6)
            tk.Label(row, text=key, fg=C["faint"], bg=C["surface"],
                     font=("Segoe UI", 8), width=26, anchor="w").pack(side=tk.LEFT)
            pct_lbl = tk.Label(row, text=f"{val:.3f}", fg=C[color],
                               bg=C["surface"],
                               font=("Consolas", 9, "bold"), width=7, anchor="e")
            pct_lbl.pack(side=tk.RIGHT)
            bar = tk.Canvas(row, bg=C["card2"], height=7,
                            highlightthickness=0, bd=0)
            bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(0, 8))
            fc, fv = C[color], min(val, 1.0)
            def _db(e=None, _b=bar, _fc=fc, _fv=fv):
                _b.delete("all")
                w = _b.winfo_width()
                if w < 2: return
                fw = max(0, round(_fv * w))
                if fw: _b.create_rectangle(0, 0, fw, 7, fill=_fc, outline="")
            bar.bind("<Configure>", _db);  bar.after(20, _db)

        def _metric_row(parent, key: str, val: float, color: str, desc: str,
                        thresholds: tuple = (0.85, 0.70)):
            """Enhanced bar row with quality badge + description line."""
            good_t, fair_t = thresholds
            if val >= good_t:
                badge, badge_clr = "GOOD", "green"
            elif val >= fair_t:
                badge, badge_clr = "FAIR", "yellow"
            else:
                badge, badge_clr = "WEAK", "red"

            outer = tk.Frame(parent, bg=C["surface"])
            outer.pack(fill=tk.X, padx=16, pady=3)

            top = tk.Frame(outer, bg=C["surface"])
            top.pack(fill=tk.X)
            tk.Label(top, text=key, fg=C["faint"], bg=C["surface"],
                     font=("Segoe UI", 8), width=22, anchor="w").pack(side=tk.LEFT)
            tk.Label(top, text=f" {badge} ", fg=C["bg"], bg=C[badge_clr],
                     font=("Segoe UI", 7, "bold"), padx=2).pack(side=tk.LEFT, padx=(0, 6))
            tk.Label(top, text=f"{val:.4f}", fg=C[color], bg=C["surface"],
                     font=("Consolas", 9, "bold")).pack(side=tk.RIGHT)

            mbar = tk.Canvas(outer, bg=C["card2"], height=6,
                             highlightthickness=0, bd=0)
            mbar.pack(fill=tk.X, pady=(3, 1))
            fc2, fv2 = C[color], min(val, 1.0)
            def _dm(e=None, _b=mbar, _fc=fc2, _fv=fv2):
                _b.delete("all")
                w = _b.winfo_width()
                if w < 2:
                    return
                fw = max(0, round(_fv * w))
                if fw:
                    _b.create_rectangle(0, 0, fw, 6, fill=_fc, outline="")
            mbar.bind("<Configure>", _dm)
            mbar.after(20, _dm)

            if desc:
                tk.Label(outer, text=desc, fg=C["muted"], bg=C["surface"],
                         font=("Segoe UI", 7), anchor="w").pack(
                             anchor="w", pady=(0, 4))

        def _tip_card():
            tip_f = tk.Frame(pad, bg=C["card"])
            tip_f.pack(fill=tk.X, pady=(24, 8))
            tk.Frame(tip_f, bg=C["blue"], height=3).pack(fill=tk.X)
            tip_i = tk.Frame(tip_f, bg=C["card"])
            tip_i.pack(fill=tk.X, padx=16, pady=12)
            tk.Label(tip_i, text="Improve Accuracy",
                     fg=C["blue"], bg=C["card"],
                     font=("Segoe UI", 9, "bold")).pack(anchor="w")
            tk.Label(tip_i,
                     text="Retrain with more data anytime:\n"
                          "  Tools  →  Update ML Model        (built-in dataset)\n"
                          "  Tools  →  Update ML + Kaggle     (adds real-world malware samples)",
                     fg=C["muted"], bg=C["card"],
                     font=("Segoe UI", 8), justify=tk.LEFT).pack(anchor="w", pady=(6, 0))
            btn_row = tk.Frame(tip_f, bg=C["card"])
            btn_row.pack(fill=tk.X, padx=16, pady=(8, 14))
            for lbl, cmd, bg_, fg_ in (
                ("  Train (built-in)  ", lambda: self._update_ml(False),
                 C["green"], C["bg"]),
                ("  Train + Kaggle  ", lambda: self._update_ml(True),
                 C["card2"], C["text"]),
            ):
                b = tk.Button(btn_row, text=lbl, command=cmd,
                              bg=bg_, fg=fg_,
                              activebackground=C["card2"],
                              activeforeground=C["white"],
                              font=("Segoe UI", 8, "bold"),
                              relief=tk.FLAT, bd=0,
                              padx=12, pady=6, cursor="hand2")
                b.pack(side=tk.LEFT, padx=(0, 8))

        # ═════════════════════════════════════════════════════
        # SECTION 1 — ABOUT THIS MODEL  (always shown)
        # ═════════════════════════════════════════════════════
        about_f = _section("ABOUT THIS MODEL")
        about_body = tk.Frame(about_f, bg=C["surface"])
        about_body.pack(fill=tk.X, padx=16, pady=12)
        tk.Label(about_body,
                 text="ShieldScan's ML Classifier is a multi-class threat-detection engine trained on labeled "
                      "Windows security findings. It examines every finding the scanner raises and assigns it "
                      "to one of 10 threat categories — or marks it BENIGN — then returns a confidence score "
                      "(0–1), MITRE ATT&CK technique IDs, and step-by-step remediation guidance.",
                 fg=C["text"], bg=C["surface"],
                 font=("Segoe UI", 9), wraplength=740,
                 justify=tk.LEFT).pack(anchor="w")
        tk.Label(about_body,
                 text="All inference runs 100 % locally.  No data is ever sent to any server or cloud API.",
                 fg=C["green"], bg=C["surface"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(8, 0))
        tk.Frame(about_f, bg=C["bg"], height=6).pack(fill=tk.X)

        # ═════════════════════════════════════════════════════
        # SECTION 2 — ARCHITECTURE  (always shown)
        # ═════════════════════════════════════════════════════
        arch_f = _section("MODEL ARCHITECTURE")
        arch_body = tk.Frame(arch_f, bg=C["surface"])
        arch_body.pack(fill=tk.X, padx=16, pady=10)

        # Pipeline diagram
        diag = tk.Frame(arch_body, bg=C["card2"])
        diag.pack(fill=tk.X, pady=(0, 8))
        diag_inner = tk.Frame(diag, bg=C["card2"])
        diag_inner.pack(fill=tk.X, padx=16, pady=14)
        for i, (icon, label, desc, color) in enumerate((
            ("①", "Input Finding",     "Dict: reason, severity, port, name, scan_type",              "muted"),
            ("②", "Feature Extraction","35-dim numeric vector  (keyword flags, port heuristics…)",    "blue"),
            ("③", "StandardScaler",    "Z-score normalisation across all 35 features",                "muted"),
            ("④", "Random Forest",     "500 trees · sqrt features · balanced class weights",          "green"),
            ("⑤", "Output",            "Threat category  +  confidence (0–1)  +  MITRE + steps",      "orange"),
        )):
            step_row = tk.Frame(diag_inner, bg=C["card2"])
            step_row.pack(fill=tk.X, pady=2)
            tk.Label(step_row, text=icon,  fg=C[color], bg=C["card2"],
                     font=("Segoe UI", 12)).pack(side=tk.LEFT, padx=(0, 10))
            right_col = tk.Frame(step_row, bg=C["card2"])
            right_col.pack(side=tk.LEFT, fill=tk.X, expand=True)
            tk.Label(right_col, text=label, fg=C["white"], bg=C["card2"],
                     font=("Segoe UI", 9, "bold"), anchor="w").pack(anchor="w")
            tk.Label(right_col, text=desc,  fg=C["muted"], bg=C["card2"],
                     font=("Segoe UI", 8),  anchor="w").pack(anchor="w")
            if i < 4:
                tk.Label(diag_inner, text="    ↓", fg=C["faint"], bg=C["card2"],
                         font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 2))

        # Random Forest hyperparameter card
        models_hdr = tk.Frame(arch_body, bg=C["surface"])
        models_hdr.pack(fill=tk.X, pady=(10, 4))
        tk.Label(models_hdr, text="Random Forest — hyperparameters",
                 fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")

        for param_name, param_val, p_color in (
            ("n_estimators",      "500",                   "green"),
            ("max_depth",         "None  (fully grown)",   "blue"),
            ("max_features",      "sqrt  (default)",       "blue"),
            ("class_weight",      "balanced",              "orange"),
            ("min_samples_split", "2",                     "muted"),
            ("min_samples_leaf",  "1",                     "muted"),
            ("random_state",      "42",                    "muted"),
            ("n_jobs",            "-1  (all CPU cores)",   "teal"),
        ):
            p_row = tk.Frame(arch_body, bg=C["surface"])
            p_row.pack(fill=tk.X, pady=1)
            tk.Label(p_row, text=f"  {param_name:<22}", fg=C["faint"], bg=C["surface"],
                     font=("Consolas", 8)).pack(side=tk.LEFT)
            tk.Label(p_row, text=param_val, fg=C[p_color], bg=C["surface"],
                     font=("Consolas", 8, "bold")).pack(side=tk.LEFT)

        # Why RF was chosen
        why_row = tk.Frame(arch_body, bg=C["card2"])
        why_row.pack(fill=tk.X, pady=(12, 4))
        why_inner = tk.Frame(why_row, bg=C["card2"])
        why_inner.pack(fill=tk.X, padx=14, pady=10)
        tk.Label(why_inner,
                 text="Benchmark result — why Random Forest was chosen:",
                 fg=C["green"], bg=C["card2"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        for model_nm, acc_v, f1_v, chosen in (
            ("Random Forest",     "0.9389", "0.9466", True),
            ("Extra Trees",       "0.9222", "0.9306", False),
            ("XGBoost",           "0.8889", "0.8992", False),
            ("Gradient Boosting", "0.8889", "0.8922", False),
            ("Stacking Ensemble", "0.8722", "0.8841", False),
        ):
            clr  = "green" if chosen else "faint"
            flag = "  <- selected" if chosen else ""
            tk.Label(why_inner,
                     text=f"  {'*' if chosen else '-'}  {model_nm:<22}  acc {acc_v}   F1 {f1_v}{flag}",
                     fg=C[clr], bg=C["card2"],
                     font=("Consolas", 8)).pack(anchor="w", pady=1)
        tk.Label(why_inner,
                 text="Stacking added meta-learner noise on this small dataset (180 samples, 16 classes).",
                 fg=C["muted"], bg=C["card2"],
                 font=("Segoe UI", 7, "italic")).pack(anchor="w", pady=(6, 0))

        tk.Frame(arch_f, bg=C["bg"], height=6).pack(fill=tk.X)

        # ═════════════════════════════════════════════════════
        # SECTION 3 — FEATURE ENGINEERING  (always shown)
        # ═════════════════════════════════════════════════════
        feat_f = _section("FEATURE ENGINEERING  (35 features)")
        feat_intro = tk.Frame(feat_f, bg=C["surface"])
        feat_intro.pack(fill=tk.X, padx=16, pady=(8, 4))
        tk.Label(feat_intro,
                 text="Every scanner finding is converted into a 35-dimensional numeric vector "
                      "before classification.  Features are grouped below by function.",
                 fg=C["muted"], bg=C["surface"],
                 font=("Segoe UI", 8), wraplength=740).pack(anchor="w")

        feature_groups = [
            ("Scan Context", "blue", [
                ("#0   scan_type",          "Numeric ID of the scanner module (Process=0, Driver=1, …)"),
                ("#1   severity",           "Finding severity: HIGH=3, MEDIUM=2, LOW=1, INFO=0"),
            ]),
            ("Network / Port", "green", [
                ("#2   port",               "Raw port number (0 when not applicable)"),
                ("#3   well_known_port",     "1 if port is in range 1 – 1 023"),
                ("#4   registered_port",     "1 if port is in range 1 024 – 49 151"),
                ("#5   malware_port",        "1 if port matches known C2 set: 4444, 1337, 31337, 9001 …"),
            ]),
            ("Process Identity", "orange", [
                ("#6   is_system_process",   "1 if name matches known Windows system process"),
                ("#7   name_length",         "Character length of process / driver name (capped 64)"),
                ("#8   reason_length",       "Character length of the finding reason (capped 256)"),
            ]),
            ("Process Hiding", "red", [
                ("#9   hidden_from_kw",      "'hidden from' or 'hidden but' in reason text"),
                ("#10  absent_psutil",       "'absent from psutil' or 'hidden from psutil'"),
                ("#11  wmic_kw",             "'wmic' mentioned in reason"),
                ("#12  netstat_kw",          "'netstat' mentioned in reason"),
                ("#13  kernel_evasion",      "'kernel-level evasion' or 'kernel evasion'"),
                ("#31  vis_psutil_absent",   "'visible in psutil but absent' (WMIC-vs-psutil check)"),
                ("#32  vis_wmic_absent",     "'visible in wmic but absent from psutil'"),
                ("#33  vis_netstat_absent",  "'visible in netstat but absent'"),
                ("#34  vis_psutil_no_net",   "'visible in psutil but absent from netstat'"),
            ]),
            ("Masquerade & Injection", "purple", [
                ("#14  masquerade",          "'masquerade', 'wrong path', 'wrong location', 'expected c:\\\\windows'"),
                ("#15  injection_kw",        "'inject', 'injected', or 'injection' in reason"),
                ("#16  dll_kw",              "' dll ' substring present in reason"),
            ]),
            ("Suspicious Paths", "yellow", [
                ("#17  temp_path",           "Path contains \\\\temp\\\\, \\\\tmp\\\\, appdata\\\\local\\\\temp"),
                ("#18  user_writable_path",  "AppData\\\\Roaming/Local, \\\\Public\\\\, Downloads, Desktop"),
                ("#28  suspicious_path_kw",  "'suspicious path', 'unusual location', 'non-standard'"),
            ]),
            ("Code Signing", "blue", [
                ("#19  unsigned",            "'unsigned', 'not signed', 'no valid signature', 'revoked', 'expired'"),
            ]),
            ("Process Relationships", "green", [
                ("#20  parent_ppid",         "'parent', 'parented by', or 'ppid' in reason"),
            ]),
            ("Persistence", "orange", [
                ("#21  run_key",             "HKCU/HKLM Run or RunOnce registry key reference"),
                ("#22  winlogon_shell",      "'winlogon', 'userinit', 'shell value'"),
                ("#23  ifeo_debugger",       "'ifeo', 'debugger', 'image file execution options'"),
                ("#27  persist_autorun",     "'persist', 'startup', 'autorun', 'autostart', 'boot'"),
            ]),
            ("Command & Control", "red", [
                ("#24  c2_kw",               "'malware port', 'c2', 'command and control', 'known malware'"),
                ("#25  orphan_socket",       "'orphan socket', 'no owning process'"),
            ]),
            ("Kernel & Memory", "purple", [
                ("#26  kernel_hooks",        "'ssdt', 'idt', 'irp', 'hook', 'dkom', 'activeprocesslinks'"),
                ("#29  evasion_kw",          "'evasion' or 'evade' in reason"),
                ("#30  memory_artifact",     "'malfind', 'page_execute_readwrite', 'shellcode', 'reflective', 'hollowing'"),
            ]),
        ]

        for grp_name, grp_color, feats in feature_groups:
            grp_outer = tk.Frame(feat_f, bg=C["surface"])
            grp_outer.pack(fill=tk.X, padx=16, pady=(10, 2))
            # Group header
            gh = tk.Frame(grp_outer, bg=C["surface"])
            gh.pack(fill=tk.X, pady=(0, 4))
            tk.Frame(gh, bg=C[grp_color], width=3, height=16).pack(side=tk.LEFT)
            tk.Label(gh, text=f"  {grp_name}  ({len(feats)})",
                     fg=C[grp_color], bg=C["surface"],
                     font=("Segoe UI", 8, "bold")).pack(side=tk.LEFT)
            # Feature rows (alternating shading)
            for j, (feat_id, desc) in enumerate(feats):
                row_bg = C["card2"] if j % 2 == 0 else C["surface"]
                f_row = tk.Frame(grp_outer, bg=row_bg)
                f_row.pack(fill=tk.X)
                tk.Label(f_row, text=feat_id,
                         fg=C["faint"], bg=row_bg,
                         font=("Consolas", 8),
                         width=22, anchor="w",
                         padx=6, pady=3).pack(side=tk.LEFT)
                tk.Label(f_row, text=desc,
                         fg=C["text"], bg=row_bg,
                         font=("Segoe UI", 8), anchor="w",
                         padx=4, pady=3).pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Frame(feat_f, bg=C["bg"], height=6).pack(fill=tk.X)

        # ═════════════════════════════════════════════════════
        # SECTION 4 — DETECTION CATEGORIES  (always shown)
        # ═════════════════════════════════════════════════════
        cats_f = _section("DETECTION CATEGORIES  (10 classes)")
        cat_intro = tk.Frame(cats_f, bg=C["surface"])
        cat_intro.pack(fill=tk.X, padx=16, pady=(8, 4))
        tk.Label(cat_intro,
                 text="The classifier assigns each finding to exactly one of these categories. "
                      "MITRE ATT&CK technique IDs are shown for threat classes.",
                 fg=C["muted"], bg=C["surface"],
                 font=("Segoe UI", 8), wraplength=740).pack(anchor="w")

        categories = [
            ("PROCESS_HIDING",    "red",    "T1014, T1055",
             "Process visible in one enumeration API but hidden from another — classic rootkit technique."),
            ("PROCESS_MASQUERADE","red",    "T1036.005",
             "System process name running from an unexpected directory — impersonation tactic."),
            ("PARENT_ANOMALY",    "red",    "T1055, T1134",
             "Critical Windows process has the wrong parent — process injection or hollowing indicator."),
            ("TEMP_EXECUTION",    "yellow", "T1204.002, T1059",
             "Executable running from %TEMP%, AppData, Downloads or other user-writable paths."),
            ("DLL_INJECTION",     "yellow", "T1055.001, T1574.002",
             "DLL loaded by a process was found in a suspicious location (side-loading or injection)."),
            ("DRIVER_HIDDEN",     "red",    "T1014, T1215",
             "Kernel driver visible in one source but absent from another — kernel-mode rootkit."),
            ("NETWORK_C2",        "orange", "T1095, T1071",
             "Network connection to a known C2 port or flagged command-and-control activity."),
            ("REGISTRY_PERSIST",  "orange", "T1547.001, T1546",
             "Run key, Winlogon, IFEO or shell-value modification — persistence mechanism."),
            ("MEMORY_ARTIFACT",   "purple", "T1055, T1620",
             "Malfind hit, RWX memory region, shellcode or reflective DLL found in process memory."),
            ("BENIGN",            "green",  "—",
             "Finding is a known-good artefact or below the confidence threshold for alerting."),
        ]

        for i, (cat, color, mitre, desc) in enumerate(categories):
            row_bg = C["card2"] if i % 2 == 0 else C["surface"]
            cat_row = tk.Frame(cats_f, bg=row_bg)
            cat_row.pack(fill=tk.X)
            # Left accent bar
            tk.Frame(cat_row, bg=C[color], width=3).pack(side=tk.LEFT, fill=tk.Y)
            body = tk.Frame(cat_row, bg=row_bg)
            body.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=12, pady=8)
            top = tk.Frame(body, bg=row_bg)
            top.pack(fill=tk.X)
            tk.Label(top, text=cat,   fg=C[color], bg=row_bg,
                     font=("Consolas", 9, "bold")).pack(side=tk.LEFT)
            tk.Label(top, text=f"  MITRE: {mitre}", fg=C["faint"], bg=row_bg,
                     font=("Segoe UI", 7)).pack(side=tk.LEFT, padx=(8, 0))
            tk.Label(body, text=desc, fg=C["muted"], bg=row_bg,
                     font=("Segoe UI", 8), anchor="w",
                     wraplength=700, justify=tk.LEFT).pack(anchor="w", pady=(2, 0))

        tk.Frame(cats_f, bg=C["bg"], height=6).pack(fill=tk.X)

        # ═════════════════════════════════════════════════════
        # MODEL METRICS — conditional on meta existing
        # ═════════════════════════════════════════════════════
        if not meta:
            no_model = tk.Frame(pad, bg=C["card"])
            no_model.pack(fill=tk.X, pady=(10, 4))
            tk.Frame(no_model, bg=C["yellow"], height=3).pack(fill=tk.X)
            nm_i = tk.Frame(no_model, bg=C["card"])
            nm_i.pack(fill=tk.X, padx=20, pady=16)
            tk.Label(nm_i, text="Model Not Yet Trained",
                     fg=C["yellow"], bg=C["card"],
                     font=("Segoe UI", 11, "bold")).pack(anchor="w")
            tk.Label(nm_i,
                     text="Train once to unlock: CV accuracy, F1 scores, AUC-ROC, "
                          "per-class precision / recall, and training data statistics.",
                     fg=C["muted"], bg=C["card"],
                     font=("Segoe UI", 9),
                     wraplength=700, justify=tk.LEFT).pack(anchor="w", pady=(6, 12))
            train_btn = tk.Button(nm_i, text="  ▶  Train Now  ",
                                  command=lambda: self._update_ml(False),
                                  bg=C["green"], fg=C["bg"],
                                  activebackground="#4ac760",
                                  font=("Segoe UI", 10, "bold"),
                                  relief=tk.FLAT, bd=0, padx=16, pady=10,
                                  cursor="hand2")
            train_btn.pack(anchor="w")
            _tip_card()
            return

        # ── Hero metric cards ─────────────────────────────────
        acc     = meta.get("cv_accuracy", 0)
        f1_mac  = meta.get("f1_macro", 0)
        auc     = meta.get("auc_roc", 0)
        std     = meta.get("cv_std", 0)

        tk.Label(pad, text="MODEL PERFORMANCE",
                 fg=C["muted"], bg=C["bg"],
                 font=("Segoe UI", 9, "bold"),
                 anchor="w").pack(fill=tk.X, pady=(22, 6))
        tk.Frame(pad, bg=C["border"], height=1).pack(fill=tk.X)

        hero_row = tk.Frame(pad, bg=C["bg"])
        hero_row.pack(fill=tk.X, pady=(4, 8))
        for val, label, sublabel, color in (
            (f"{acc:.1%}", "CV Accuracy", f"std  ± {std:.3f}", "green"),
            (f"{f1_mac:.3f}", "F1 Macro", "Macro-averaged F1", "blue"),
            (f"{auc:.3f}" if auc else "N/A", "AUC-ROC", "OvR macro avg", "purple"),
            (str(meta.get("classes", "—")), "Classes", "Distinct labels", "orange"),
        ):
            co = tk.Frame(hero_row, bg=C[color])
            co.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=(0, 4))
            tk.Frame(co, bg=C[color], height=3).pack(fill=tk.X)
            cb = tk.Frame(co, bg=C["card"])
            cb.pack(fill=tk.BOTH, expand=True)
            inn = tk.Frame(cb, bg=C["card"])
            inn.pack(fill=tk.X, padx=14, pady=(10, 12))
            tk.Label(inn, text=label,    fg=C["faint"], bg=C["card"],
                     font=("Segoe UI", 8)).pack(anchor="w")
            tk.Label(inn, text=val,      fg=C[color],  bg=C["card"],
                     font=("Consolas", 22, "bold")).pack(anchor="w", pady=(4, 0))
            tk.Label(inn, text=sublabel, fg=C["faint"], bg=C["card"],
                     font=("Segoe UI", 7)).pack(anchor="w", pady=(2, 0))

        # ── Missing-metrics banner ────────────────────────────
        _metrics_missing = (f1_mac == 0 and acc > 0)
        if _metrics_missing:
            miss_card = tk.Frame(pad, bg=C["yellow"], relief=tk.FLAT)
            miss_card.pack(fill=tk.X, pady=(6, 2))
            tk.Frame(miss_card, bg=C["yellow"], height=2).pack(fill=tk.X)
            miss_inner = tk.Frame(miss_card, bg=C["card"])
            miss_inner.pack(fill=tk.X)
            miss_row = tk.Frame(miss_inner, bg=C["card"])
            miss_row.pack(fill=tk.X, padx=14, pady=10)
            tk.Label(miss_row,
                     text="Extended metrics (F1, Precision, Recall) are not in saved metadata.",
                     fg=C["yellow"], bg=C["card"],
                     font=("Segoe UI", 9, "bold"),
                     anchor="w").pack(fill=tk.X)
            tk.Label(miss_row,
                     text="Click below to recompute them in the background (~30 s). "
                          "The model is NOT retrained — existing weights are reused.",
                     fg=C["muted"], bg=C["card"],
                     font=("Segoe UI", 8),
                     anchor="w", wraplength=600, justify=tk.LEFT).pack(fill=tk.X, pady=(3, 0))
            tk.Button(miss_row,
                      text="Recompute OOF Metrics Now",
                      command=self._recompute_oof_metrics,
                      bg=C["yellow"], fg=C["bg"],
                      activebackground="#f0c030",
                      activeforeground=C["bg"],
                      font=("Segoe UI", 9, "bold"),
                      relief=tk.FLAT, bd=0,
                      padx=14, pady=7,
                      cursor="hand2").pack(anchor="w", pady=(8, 0))

        # ── Radar / spider chart ──────────────────────────────
        import math as _math

        f1_wt = meta.get("f1_weighted",     0)
        prec  = meta.get("precision_macro", 0)
        rec   = meta.get("recall_macro",    0)

        _has_ext = f1_mac > 0 or prec > 0 or rec > 0
        _radar_metrics = [
            ("Accuracy",  acc),
            ("F1 Macro",  f1_mac  if _has_ext else 0),
            ("F1 Wt.",    f1_wt   if _has_ext else 0),
            ("Precision", prec    if _has_ext else 0),
            ("Recall",    rec     if _has_ext else 0),
        ]
        if auc:
            _radar_metrics.append(("AUC-ROC", auc))

        tk.Label(pad, text="PERFORMANCE RADAR",
                 fg=C["muted"], bg=C["bg"],
                 font=("Segoe UI", 9, "bold"),
                 anchor="w").pack(fill=tk.X, pady=(16, 6))
        tk.Frame(pad, bg=C["border"], height=1).pack(fill=tk.X)

        radar_card = tk.Frame(pad, bg=C["surface"])
        radar_card.pack(fill=tk.X, pady=(1, 0))
        radar_inner = tk.Frame(radar_card, bg=C["surface"])
        radar_inner.pack(fill=tk.X, padx=16, pady=12)

        radar_cv = tk.Canvas(radar_inner, bg=C["surface"], height=230,
                             highlightthickness=0, bd=0)
        radar_cv.pack(fill=tk.X)

        def _draw_radar(event=None, _cv=radar_cv, _md=_radar_metrics, _he=_has_ext):
            _cv.delete("all")
            cw = _cv.winfo_width()
            ch = _cv.winfo_height()
            if cw < 40 or ch < 40:
                return
            n   = len(_md)
            cx  = cw // 2
            cy  = ch // 2
            r   = max(20, min(cx - 52, cy - 36))

            # Grid polygons + level labels
            for level, lbl in ((0.25, ".25"), (0.5, ".50"), (0.75, ".75"), (1.0, "1.0")):
                gpts = []
                for i in range(n):
                    ang = _math.pi / 2 - 2 * _math.pi * i / n
                    gpts.extend([cx + r * level * _math.cos(ang),
                                  cy - r * level * _math.sin(ang)])
                if len(gpts) >= 6:
                    _cv.create_polygon(gpts, outline=C["border"], fill="", width=1)
                # Level label on the 12 o'clock axis
                lx = cx + 4
                ly = cy - r * level - 9
                _cv.create_text(lx, ly, text=lbl, fill=C["faint"],
                                font=("Segoe UI", 7), anchor="w")

            # Axis spokes + labels
            for i, (name, val) in enumerate(_md):
                ang = _math.pi / 2 - 2 * _math.pi * i / n
                ax  = cx + r * _math.cos(ang)
                ay  = cy - r * _math.sin(ang)
                _cv.create_line(cx, cy, ax, ay, fill=C["border"], width=1)
                lx  = cx + (r + 30) * _math.cos(ang)
                ly  = cy - (r + 30) * _math.sin(ang)
                clr = (C["green"] if val >= 0.85 else
                       C["yellow"] if val >= 0.70 else C["red"])
                _cv.create_text(lx, ly,
                                text=f"{name}\n{val:.3f}",
                                fill=clr,
                                font=("Segoe UI", 7, "bold"),
                                justify="center")

            # Filled data polygon
            dpts = []
            for i, (_, val) in enumerate(_md):
                ang = _math.pi / 2 - 2 * _math.pi * i / n
                rv  = min(val, 1.0) * r
                dpts.extend([cx + rv * _math.cos(ang),
                              cy - rv * _math.sin(ang)])
            if len(dpts) >= 6:
                _cv.create_polygon(dpts, fill=C["z_blue"],
                                   outline=C["blue"], width=2)

            # Dots at each vertex
            for i, (_, val) in enumerate(_md):
                ang  = _math.pi / 2 - 2 * _math.pi * i / n
                rv   = min(val, 1.0) * r
                dx   = cx + rv * _math.cos(ang)
                dy   = cy - rv * _math.sin(ang)
                dclr = (C["green"] if val >= 0.85 else
                        C["yellow"] if val >= 0.70 else C["red"])
                _cv.create_oval(dx - 4, dy - 4, dx + 4, dy + 4,
                                fill=dclr, outline=C["bg"], width=1)

            if not _he:
                _cv.create_text(cx, cy + 18,
                                text="Extended metrics not yet computed",
                                fill=C["yellow"],
                                font=("Segoe UI", 8, "italic"),
                                anchor="center")

        radar_cv.bind("<Configure>", _draw_radar)
        radar_cv.after(80, _draw_radar)

        # Benchmark note
        bench_row = tk.Frame(radar_card, bg=C["surface"])
        bench_row.pack(fill=tk.X, padx=16, pady=(0, 10))
        tk.Label(bench_row, text="Benchmark:",
                 fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 7, "bold")).pack(side=tk.LEFT)
        tk.Label(bench_row,
                 text="  Industry baseline for multi-class malware detection: "
                      "~0.75 F1 Macro · ~0.82 AUC-ROC (Ucci et al., 2019)",
                 fg=C["muted"], bg=C["surface"],
                 font=("Segoe UI", 7)).pack(side=tk.LEFT)

        # Colour legend
        leg_row = tk.Frame(radar_card, bg=C["surface"])
        leg_row.pack(fill=tk.X, padx=16, pady=(0, 12))
        for lbl, clr in (("≥ 0.85 Good", "green"),
                         ("≥ 0.70 Fair", "yellow"),
                         ("< 0.70 Weak", "red")):
            tk.Label(leg_row, text="●", fg=C[clr], bg=C["surface"],
                     font=("Segoe UI", 9)).pack(side=tk.LEFT)
            tk.Label(leg_row, text=f" {lbl}   ", fg=C["faint"], bg=C["surface"],
                     font=("Segoe UI", 7)).pack(side=tk.LEFT)

        # ── Performance metrics with quality badges ────────────
        met_f = _section(
            "PERFORMANCE METRICS  (5-fold cross-validation)")

        # CV Accuracy special row (shows ± std)
        acc_outer = tk.Frame(met_f, bg=C["surface"])
        acc_outer.pack(fill=tk.X, padx=16, pady=3)
        acc_top = tk.Frame(acc_outer, bg=C["surface"])
        acc_top.pack(fill=tk.X)
        tk.Label(acc_top, text="CV Accuracy", fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 8), width=22, anchor="w").pack(side=tk.LEFT)
        _acc_badge = ("GOOD" if acc >= 0.88 else "FAIR" if acc >= 0.75 else "WEAK")
        _acc_bc    = ("green"  if acc >= 0.88 else "yellow" if acc >= 0.75 else "red")
        tk.Label(acc_top, text=f" {_acc_badge} ", fg=C["bg"], bg=C[_acc_bc],
                 font=("Segoe UI", 7, "bold"), padx=2).pack(side=tk.LEFT, padx=(0, 6))
        tk.Label(acc_top, text=f"{acc:.4f}  ±  {std:.4f}",
                 fg=C["green"], bg=C["surface"],
                 font=("Consolas", 9, "bold")).pack(side=tk.RIGHT)
        acc_bar = tk.Canvas(acc_outer, bg=C["card2"], height=6,
                            highlightthickness=0, bd=0)
        acc_bar.pack(fill=tk.X, pady=(3, 1))
        def _da(e=None, _b=acc_bar, _v=acc):
            _b.delete("all")
            w = _b.winfo_width()
            if w < 2: return
            fw = max(0, round(min(_v, 1.0) * w))
            if fw: _b.create_rectangle(0, 0, fw, 6, fill=C["green"], outline="")
        acc_bar.bind("<Configure>", _da); acc_bar.after(20, _da)
        tk.Label(acc_outer,
                 text="Mean classification accuracy across 5 stratified folds. "
                      "High accuracy alone can be misleading for imbalanced classes.",
                 fg=C["muted"], bg=C["surface"],
                 font=("Segoe UI", 7), anchor="w").pack(anchor="w", pady=(0, 4))

        for key, attr, color, desc, thresh in (
            ("F1 Macro",
             "f1_macro",       "blue",
             "Unweighted mean of per-class F1 — penalises imbalanced classes equally. "
             "Best overall threat-detection indicator.",
             (0.85, 0.70)),
            ("F1 Weighted",
             "f1_weighted",    "blue",
             "Support-weighted mean of per-class F1 — reflects the real class distribution "
             "in your training set.",
             (0.85, 0.70)),
            ("Precision Macro",
             "precision_macro","purple",
             "Fraction of flagged findings that are genuine threats (macro avg). "
             "Low precision → many false positives.",
             (0.85, 0.70)),
            ("Recall Macro",
             "recall_macro",   "orange",
             "Fraction of genuine threats the model correctly detected (macro avg). "
             "Low recall → threats are missed.",
             (0.80, 0.65)),
        ):
            _metric_row(met_f, key, meta.get(attr, 0), color, desc, thresh)

        if "auc_roc" in meta:
            _metric_row(met_f, "AUC-ROC", meta["auc_roc"], "green",
                        "Area Under the ROC Curve (OvR macro avg). "
                        "1.0 = perfect · 0.5 = random.  Robust to class imbalance.",
                        (0.90, 0.75))
        tk.Frame(met_f, bg=C["bg"], height=6).pack(fill=tk.X)

        tk.Frame(pad, bg=C["bg"], height=16).pack(fill=tk.X)

        # ── Per-class full table ──────────────────────────────
        pc = meta.get("per_class", {})
        class_names = meta.get("class_names", [])
        if pc and class_names:
            pc_f = _section("PER-CLASS BREAKDOWN  (precision / recall / F1 / support)")

            # Table header
            hdr = tk.Frame(pc_f, bg=C["card2"])
            hdr.pack(fill=tk.X, padx=16, pady=(8, 0))
            for col_txt, col_w in (
                ("Class",     22), ("Precision", 11),
                ("Recall",    11), ("F1-Score",  11), ("Support", 9),
            ):
                tk.Label(hdr, text=col_txt,
                         fg=C["muted"], bg=C["card2"],
                         font=("Segoe UI", 8, "bold"),
                         width=col_w, anchor="w",
                         padx=8, pady=6).pack(side=tk.LEFT)

            # Data rows
            for i, cls in enumerate(class_names):
                rd   = pc.get(cls, {})
                prec = rd.get("precision", 0)
                rec  = rd.get("recall",    0)
                f1v  = rd.get("f1-score",  0)
                n    = int(rd.get("support", 0))
                fc   = ("green" if f1v >= 0.8 else
                        "yellow" if f1v >= 0.5 else "red")
                rbg  = C["surface"] if i % 2 == 0 else C["card2"]
                tr   = tk.Frame(pc_f, bg=rbg)
                tr.pack(fill=tk.X, padx=16)
                tk.Frame(tr, bg=C[fc], width=3).pack(side=tk.LEFT, fill=tk.Y)
                tk.Label(tr, text=cls,
                         fg=C[fc], bg=rbg,
                         font=("Consolas", 8, "bold"),
                         width=22, anchor="w",
                         padx=6, pady=6).pack(side=tk.LEFT)
                for v, vc in (
                    (f"{prec:.3f}", "text"),
                    (f"{rec:.3f}",  "text"),
                    (f"{f1v:.3f}",  fc),
                    (str(n),        "faint"),
                ):
                    tk.Label(tr, text=v, fg=C[vc], bg=rbg,
                             font=("Consolas", 8),
                             width=11 if vc != "faint" else 9,
                             anchor="w",
                             padx=8, pady=6).pack(side=tk.LEFT)

            # Macro avg footer
            macro = pc.get("macro avg", {})
            if macro:
                mrow = tk.Frame(pc_f, bg=C["card"])
                mrow.pack(fill=tk.X, padx=16, pady=(2, 0))
                tk.Frame(mrow, bg=C["border"], height=1).pack(fill=tk.X)
                mr_inner = tk.Frame(mrow, bg=C["card"])
                mr_inner.pack(fill=tk.X)
                tk.Label(mr_inner, text="MACRO AVG",
                         fg=C["muted"], bg=C["card"],
                         font=("Consolas", 8, "bold"),
                         width=25, anchor="w",
                         padx=6, pady=6).pack(side=tk.LEFT)
                for v in (macro.get("precision", 0),
                          macro.get("recall",    0),
                          macro.get("f1-score",  0)):
                    tk.Label(mr_inner, text=f"{v:.3f}",
                             fg=C["blue"], bg=C["card"],
                             font=("Consolas", 8, "bold"),
                             width=11, anchor="w",
                             padx=8, pady=6).pack(side=tk.LEFT)

            # Weighted avg footer
            wt_avg = pc.get("weighted avg", {})
            if wt_avg:
                wr_inner = tk.Frame(mrow, bg=C["card"])
                wr_inner.pack(fill=tk.X)
                tk.Label(wr_inner, text="WEIGHTED AVG",
                         fg=C["muted"], bg=C["card"],
                         font=("Consolas", 8, "bold"),
                         width=25, anchor="w",
                         padx=6, pady=6).pack(side=tk.LEFT)
                for v in (wt_avg.get("precision", 0),
                          wt_avg.get("recall",    0),
                          wt_avg.get("f1-score",  0)):
                    tk.Label(wr_inner, text=f"{v:.3f}",
                             fg=C["purple"], bg=C["card"],
                             font=("Consolas", 8, "bold"),
                             width=11, anchor="w",
                             padx=8, pady=6).pack(side=tk.LEFT)

            # F1 bar chart
            bars_lbl = tk.Frame(pc_f, bg=C["surface"])
            bars_lbl.pack(fill=tk.X, padx=16, pady=(14, 4))
            tk.Label(bars_lbl, text="F1-Score per class (visual):",
                     fg=C["faint"], bg=C["surface"],
                     font=("Segoe UI", 8, "bold")).pack(anchor="w")
            for cls in class_names:
                rd  = pc.get(cls, {})
                f1v = rd.get("f1-score", 0)
                clr = "green" if f1v >= 0.8 else ("yellow" if f1v >= 0.5 else "red")
                _bar_row(pc_f, cls, f1v, clr)
            tk.Frame(pc_f, bg=C["bg"], height=6).pack(fill=tk.X)

        # ── Training data & status ────────────────────────────
        info_f = _section("TRAINING DATA & STATUS")
        _kv(info_f, "Training samples",  str(meta.get("samples", "—")))
        _kv(info_f, "Distinct classes",  str(meta.get("classes", "—")))

        # Class sample distribution
        if pc and class_names:
            total_sup = sum(int(pc.get(c, {}).get("support", 0)) for c in class_names)
            for cls in class_names:
                n   = int(pc.get(cls, {}).get("support", 0))
                pct = n / total_sup * 100 if total_sup else 0
                _kv(info_f, f"    {cls}", f"{n}  ({pct:.1f}%)", "faint")

        trained = meta.get("trained_at", "")
        if trained:
            try:
                trained = datetime.fromisoformat(trained).strftime("%d %b %Y  %H:%M")
            except Exception:
                pass
        _kv(info_f, "Trained at",         trained or "—")
        _kv(info_f, "Architecture",        "Random Forest", "green")
        _kv(info_f, "Ensemble stacking",  "No", "faint")

        try:
            from ml_model.threat_model import ThreatClassifier as _TC
            _is_stale = _TC().is_stale()
        except Exception:
            _is_stale = False
        _kv(info_f, "Model freshness",
            "Stale  (> 30 d old — retrain recommended)" if _is_stale
            else "Up to date",
            "yellow" if _is_stale else "green")
        tk.Frame(info_f, bg=C["bg"], height=6).pack(fill=tk.X)

        _tip_card()

    # ══════════════════════════════════════════════════════════
    # Right panel — meter + stats
    # ══════════════════════════════════════════════════════════

    def _build_right(self, parent) -> tk.Frame:
        outer = tk.Frame(parent, bg=C["surface"], width=234)
        outer.pack_propagate(False)

        # Slim scrollbar + canvas so all content is reachable
        _rvsb = ttk.Scrollbar(outer, style="Slim.Vertical.TScrollbar",
                               orient=tk.VERTICAL)
        _rvsb.pack(side=tk.RIGHT, fill=tk.Y)
        _rc = tk.Canvas(outer, bg=C["surface"],
                        highlightthickness=0, bd=0)
        _rc.configure(yscrollcommand=_rvsb.set)
        _rvsb.configure(command=_rc.yview)
        _rc.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        _scroll_host = tk.Frame(_rc, bg=C["surface"])
        _wid = _rc.create_window((0, 0), window=_scroll_host, anchor="nw")
        _scroll_host.bind("<Configure>",
                          lambda e: _rc.configure(
                              scrollregion=_rc.bbox("all")))
        _rc.bind("<Configure>",
                 lambda e: _rc.itemconfig(_wid, width=e.width))

        # MouseWheel: this panel takes ownership on hover, yields on leave
        def _rc_wheel(e): _rc.yview_scroll(int(-1*(e.delta/120)), "units")
        def _rc_enter(_): _rc.bind_all("<MouseWheel>", _rc_wheel)
        def _rc_leave(_):
            # Yield back to history canvas (created later — resolve lazily)
            try:
                hc = self._hist_canvas
                hc.bind_all("<MouseWheel>",
                            lambda e: hc.yview_scroll(
                                int(-1*(e.delta/120)), "units"))
            except AttributeError:
                _rc.unbind_all("<MouseWheel>")
        outer.bind("<Enter>", _rc_enter)
        outer.bind("<Leave>", _rc_leave)

        inner = tk.Frame(_scroll_host, bg=C["surface"])
        inner.pack(fill=tk.BOTH, expand=True, padx=16)

        # ── Risk meter ────────────────────────────────────────
        self._slabel(inner, "RISK SCORE")

        # Large score label
        score_row = tk.Frame(inner, bg=C["surface"])
        score_row.pack(fill=tk.X, pady=(0, 4))
        self._lbl_score_big = tk.Label(score_row, text="—",
                                        fg=C["faint"], bg=C["surface"],
                                        font=("Consolas", 34, "bold"))
        self._lbl_score_big.pack(side=tk.LEFT)
        tk.Label(score_row, text=" / 100",
                 fg=C["faint"], bg=C["surface"],
                 font=("Consolas", 11)).pack(side=tk.LEFT,
                                             pady=(14, 0))

        self._lbl_verdict = tk.Label(inner, text="Run a scan to begin.",
                                      fg=C["faint"], bg=C["surface"],
                                      font=("Segoe UI", 9, "bold"),
                                      wraplength=200, justify=tk.LEFT)
        self._lbl_verdict.pack(anchor="w", fill=tk.X)
        self._lbl_verdict_desc = tk.Label(inner, text="",
                                           fg=C["muted"], bg=C["surface"],
                                           font=("Segoe UI", 8),
                                           wraplength=200, justify=tk.LEFT)
        self._lbl_verdict_desc.pack(anchor="w", pady=(2, 10), fill=tk.X)

        # Meter canvas
        self._meter = tk.Canvas(inner, height=58,
                                 bg=C["surface"],
                                 highlightthickness=0, bd=0)
        self._meter.pack(fill=tk.X, pady=(0, 4))
        self._meter.bind("<Configure>",
                          lambda _: self._draw_meter(
                              self._score,
                              _VERDICT_COLOR.get(self._verdict, C["faint"])))
        Tooltip(self._meter,
                "Risk meter — 0 to 100\n"
                "  Green  0–15   Clean\n"
                "  Blue   16–40  Low Risk\n"
                "  Yellow 41–60  Suspicious\n"
                "  Red    61–100 Compromised")

        # Zone legend
        leg = tk.Frame(inner, bg=C["surface"])
        leg.pack(fill=tk.X, pady=(2, 0))
        for clr, label in (
            (C["green"],  "Clean"),
            (C["blue"],   "Low"),
            (C["yellow"], "Susp."),
            (C["red"],    "High"),
        ):
            f = tk.Frame(leg, bg=C["surface"])
            f.pack(side=tk.LEFT, expand=True)
            tk.Label(f, text="●", fg=clr, bg=C["surface"],
                     font=("Segoe UI", 7)).pack(side=tk.LEFT)
            tk.Label(f, text=label, fg=C["faint"], bg=C["surface"],
                     font=("Segoe UI", 7)).pack(side=tk.LEFT, padx=(1, 0))

        self._hsep(inner)

        # ── Findings breakdown ────────────────────────────────
        self._slabel(inner, "FINDINGS")
        self._count_rows: dict[str, tk.Label] = {}
        for key, ck, tip in (
            ("HIGH",  "red",    "Critical — immediate action needed."),
            ("MED",   "yellow", "Moderate — investigate soon."),
            ("LOW",   "blue",   "Low-risk — monitor over time."),
            ("TOTAL", "muted",  "Total findings across all modules."),
        ):
            rf = tk.Frame(inner, bg=C["surface"])
            rf.pack(fill=tk.X, pady=4)
            tk.Label(rf, text=key, fg=C["muted"], bg=C["surface"],
                     font=("Segoe UI", 8), anchor="w",
                     width=7).pack(side=tk.LEFT)
            val = tk.Label(rf, text="0", fg=C[ck], bg=C["surface"],
                           font=("Consolas", 15, "bold"), anchor="e")
            val.pack(side=tk.RIGHT)
            Tooltip(rf, tip)
            self._count_rows[key] = val

        self._hsep(inner)

        # ── Session info ──────────────────────────────────────
        self._slabel(inner, "SESSION INFO")
        self._info_rows: dict[str, tk.Label] = {}
        for key, val, ck in (
            ("Admin",   "Yes" if _is_admin() else "No",
             "green" if _is_admin() else "red"),
            ("Status",  "Ready",   "muted"),
            ("Elapsed", "—",       "faint"),
            ("Report",  "None",    "faint"),
        ):
            rf = tk.Frame(inner, bg=C["surface"])
            rf.pack(fill=tk.X, pady=2)
            tk.Label(rf, text=key, fg=C["faint"], bg=C["surface"],
                     font=("Segoe UI", 8), width=8,
                     anchor="w").pack(side=tk.LEFT)
            v = tk.Label(rf, text=val, fg=C[ck], bg=C["surface"],
                         font=("Segoe UI", 8, "bold"), anchor="e")
            v.pack(side=tk.RIGHT)
            self._info_rows[key] = v

        self._hsep(inner)

        # ── RAG filter status ──────────────────────────────────
        self._slabel(inner, "RAG FILTER")
        rag_frame = tk.Frame(inner, bg=C["surface"])
        rag_frame.pack(fill=tk.X, pady=2)
        try:
            from rag_filter import rag_filter as _rf
            st = _rf.stats()
            rag_status = f"Active  •  {st['total']} entries"
            rag_color  = C["green"]
        except Exception:
            rag_status = "Unavailable"
            rag_color  = C["faint"]
        tk.Label(rag_frame, text="Status", fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 8), width=8, anchor="w").pack(side=tk.LEFT)
        self._lbl_rag = tk.Label(rag_frame, text=rag_status,
                                  fg=rag_color, bg=C["surface"],
                                  font=("Segoe UI", 8, "bold"), anchor="e")
        self._lbl_rag.pack(side=tk.RIGHT)
        Tooltip(rag_frame,
                "RAG Filter — 100% LOCAL, zero data sent outside.\n\n"
                "Uses a local JSON knowledge base + fuzzy matching\n"
                "to suppress known false positives before they reach\n"
                "the findings list.  No network calls are ever made.\n\n"
                "Tools → Configure RAG Filter KB to add/edit entries.")
        self._toolbtn(inner, "Send Report by Email",
                      self._send_report_email,
                      "Email the last scan report to a configured recipient.")

        self._hsep(inner)

        # ── Quick links ───────────────────────────────────────
        self._slabel(inner, "QUICK LINKS")
        for label, cmd, tip in (
            ("Open Last Report",  self._open_report,
             "Open the HTML report in your browser."),
            ("Capture Baseline",  self._capture_baseline,
             "Save a snapshot for future comparison."),
            ("Update ML Model",   lambda: self._update_ml(False),
             "Retrain the AI classifier."),
        ):
            self._toolbtn(inner, label, cmd, tip)

        self._hsep(inner)

        # ── Scheduled scan ────────────────────────────────────
        sched_hdr = tk.Frame(inner, bg=C["surface"])
        sched_hdr.pack(fill=tk.X, pady=(0, 6))
        self._slabel(inner, "SCHEDULED SCAN")

        # Status row
        st_row = tk.Frame(inner, bg=C["surface"])
        st_row.pack(fill=tk.X, pady=2)
        tk.Label(st_row, text="Status", fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 8), width=8, anchor="w").pack(side=tk.LEFT)
        self._lbl_sched_status = tk.Label(st_row,
                                           textvariable=self._sv_sched_status,
                                           fg=C["faint"], bg=C["surface"],
                                           font=("Segoe UI", 8, "bold"),
                                           anchor="e")
        self._lbl_sched_status.pack(side=tk.RIGHT)

        # Update status label color dynamically
        def _refresh_sched_color(*_):
            val = self._sv_sched_status.get()
            clr = C["green"] if val != "Off" else C["faint"]
            self._lbl_sched_status.configure(fg=clr)
        self._sv_sched_status.trace_add("write", _refresh_sched_color)
        _refresh_sched_color()

        # Next-run row
        nxt_row = tk.Frame(inner, bg=C["surface"])
        nxt_row.pack(fill=tk.X, pady=2)
        tk.Label(nxt_row, text="Next run", fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 8), width=8, anchor="w").pack(side=tk.LEFT)
        tk.Label(nxt_row, textvariable=self._sv_sched_next,
                 fg=C["blue"], bg=C["surface"],
                 font=("Segoe UI", 8, "bold"), anchor="e").pack(side=tk.RIGHT)
        Tooltip(nxt_row,
                "Time remaining until the next scheduled scan.\n"
                "The scan runs automatically and emails the report\n"
                "to your registered address when done.")

        self._toolbtn(inner, "Configure Schedule…",
                      self._schedule_dialog,
                      "Set up automatic recurring scans.\n"
                      "Reports are emailed to your account address.")

        return outer

    # ── Flat risk meter ───────────────────────────────────────

    def _draw_meter(self, score: int, color: str):
        c  = self._meter
        cw = c.winfo_width()
        if cw < 20:
            return
        c.delete("all")

        px = 8          # horizontal padding
        bw = cw - px*2  # bar width
        by = 22         # bar top y
        bh = 16         # bar height

        # Zone background fills (dim)
        zones_bg = [
            (0,  15,  C["z_green"]),
            (15, 40,  C["z_blue"]),
            (40, 60,  C["z_yellow"]),
            (60, 100, C["z_red"]),
        ]
        for s, e, bg in zones_bg:
            x0 = px + round(s / 100 * bw)
            x1 = px + round(e / 100 * bw)
            c.create_rectangle(x0, by, x1, by + bh,
                               fill=bg, outline="")

        # Filled zones up to current score (bright)
        zones_fg = [
            (0,  15,  C["green"]),
            (15, 40,  C["blue"]),
            (40, 60,  C["yellow"]),
            (60, 100, C["red"]),
        ]
        if score > 0:
            for s, e, fg in zones_fg:
                if score <= s:
                    break
                x0 = px + round(s   / 100 * bw)
                x1 = px + round(min(score, e) / 100 * bw)
                c.create_rectangle(x0, by, x1, by + bh,
                                   fill=fg, outline="")

        # Zone dividers
        for pct in (15, 40, 60):
            dx = px + round(pct / 100 * bw)
            c.create_line(dx, by, dx, by + bh,
                          fill=C["bg"], width=1)

        # Current position marker
        if score > 0:
            mx = px + round(score / 100 * bw)
            c.create_line(mx, by - 3, mx, by + bh + 3,
                          fill=C["white"], width=2)

        # Tick labels below bar
        for pct, label in ((0, "0"), (15, "15"),
                            (40, "40"), (60, "60"), (100, "100")):
            lx = px + round(pct / 100 * bw)
            anch = "w" if pct == 0 else ("e" if pct == 100 else "center")
            c.create_text(lx, by + bh + 9,
                          text=label, anchor=anch,
                          fill=C["faint"],
                          font=("Segoe UI", 6))

    # ══════════════════════════════════════════════════════════
    # Scan mode presets
    # ══════════════════════════════════════════════════════════

    def _set_scan_mode(self, mode: str):
        self._scan_mode.set(mode)
        # Highlight the active mode button
        for m in ("quick", "full", "custom"):
            btn = getattr(self, f"_mode_btn_{m}", None)
            if btn:
                active = (m.capitalize() == mode)
                btn.configure(
                    bg=C["card2"] if active else C["card"],
                    fg=C["white"] if active else C["muted"],
                )
        if mode == "Quick":
            for mid in self._mods:
                self._mods[mid].set(mid in ("Process", "Network"))
        elif mode == "Full":
            for mid in self._mods:
                self._mods[mid].set(mid != "Baseline Diff")
        # "Custom" → do nothing; user toggles modules manually

    # ══════════════════════════════════════════════════════════
    # Theme picker
    # ══════════════════════════════════════════════════════════

    def _theme_picker(self):
        """Small popover anchored under the Theme button, screen-boundary aware."""
        pop = tk.Toplevel(self)
        pop.wm_overrideredirect(True)
        pop.attributes("-topmost", True)
        pop.configure(bg=C["card2"])

        # ── Build content first so we can measure it ──────────
        border = tk.Frame(pop, bg=C["border"], padx=1, pady=1)
        border.pack()
        inner  = tk.Frame(border, bg=C["card2"], padx=18, pady=14)
        inner.pack()

        tk.Label(inner, text="Choose Theme",
                 fg=C["muted"], bg=C["card2"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 10))

        themes_row = tk.Frame(inner, bg=C["card2"])
        themes_row.pack()

        current = _current_theme_name()

        for name, dot_color in _THEME_DOTS.items():
            col = tk.Frame(themes_row, bg=C["card2"], padx=10, pady=4)
            col.pack(side=tk.LEFT)

            is_cur = (name == current)
            dot = tk.Label(col,
                           text="⬤" if is_cur else "◯",
                           fg=dot_color, bg=C["card2"],
                           font=("Segoe UI", 20),
                           cursor="hand2")
            dot.pack()
            tk.Label(col, text=name,
                     fg=C["white"] if is_cur else C["faint"],
                     bg=C["card2"],
                     font=("Segoe UI", 7)).pack(pady=(2, 0))

            def _select(n=name, p=pop):
                p.destroy()
                if n == _current_theme_name():
                    return
                cfg = _load_app_cfg()
                cfg["theme"] = n
                _save_app_cfg(cfg)
                global C, _VERDICT_COLOR
                C = dict(_THEMES[n])
                _VERDICT_COLOR = _build_verdict_color()
                self._restart_requested = True
                self.destroy()

            for w in (col, dot) + tuple(col.winfo_children()):
                w.bind("<Button-1>", lambda _, fn=_select: fn())
            dot.bind("<Enter>", lambda _, w=dot, fc=dot_color:
                     w.configure(text="⬤", fg=fc))
            dot.bind("<Leave>", lambda _, w=dot, n2=name, fc=dot_color:
                     w.configure(text="⬤" if n2 == _current_theme_name() else "◯"))

        # ── Position: anchored below the Theme button ──────────
        self.update_idletasks()
        pop.update_idletasks()

        pw = pop.winfo_reqwidth()
        ph = pop.winfo_reqheight()

        # Anchor to the Theme button's screen coords
        try:
            btn   = self._theme_btn_ref
            btn.update_idletasks()
            bx    = btn.winfo_rootx()
            by    = btn.winfo_rooty() + btn.winfo_height() + 4
        except Exception:
            # Fallback: near the right edge of main window, just below topbar
            bx = self.winfo_rootx() + self.winfo_width() - pw - 8
            by = self.winfo_rooty() + 50

        scr_w = pop.winfo_screenwidth()
        scr_h = pop.winfo_screenheight()

        # Clamp horizontally — never overflow right edge
        tx = min(bx, scr_w - pw - 8)
        tx = max(tx, 4)

        # If no room below button, flip above it
        if by + ph + 8 > scr_h - 40:   # 40 px taskbar margin
            try:
                ty = btn.winfo_rooty() - ph - 4
            except Exception:
                ty = by - ph - 4
        else:
            ty = by
        ty = max(ty, 4)

        pop.geometry(f"+{tx}+{ty}")

        # Close when focus leaves the popover
        pop.bind("<FocusOut>", lambda _: pop.destroy())
        pop.focus_set()

    # ══════════════════════════════════════════════════════════
    # Keyboard shortcuts
    # ══════════════════════════════════════════════════════════

    def _bind_shortcuts(self):
        self.bind_all("<Control-r>",      lambda _: self._run_scan())
        self.bind_all("<Control-period>", lambda _: self._stop_scan())
        self.bind_all("<Control-h>",
                      lambda _: (self._show_output(), self._switch_tab("history")))
        self.bind_all("<Control-m>",
                      lambda _: (self._show_output(), self._switch_tab("model")))
        self.bind_all("<Control-d>",
                      lambda _: (self._show_output(), self._switch_tab("dashboard")))
        self.bind_all("<Control-e>",      lambda _: self._export_csv())
        self.bind_all("<Control-b>",      lambda _: self._capture_baseline())
        self.bind_all("<Control-comma>",  lambda _: self._settings_dialog())

    # ══════════════════════════════════════════════════════════
    # System tray icon
    # ══════════════════════════════════════════════════════════

    def _start_tray(self):
        """Launch a system-tray icon if pystray + PIL are available."""
        try:
            import pystray
            from PIL import Image as _PILImg, ImageDraw as _PILDraw

            # Draw a simple shield icon (32x32)
            size  = 32
            img   = _PILImg.new("RGBA", (size, size), (0, 0, 0, 0))
            draw  = _PILDraw.Draw(img)
            # Shield body
            pts = [(size//2, 2), (size-3, 8), (size-3, 20),
                   (size//2, size-2), (3, 20), (3, 8)]
            draw.polygon(pts, fill=(63, 185, 80, 220))

            def _restore(icon, item):
                icon.stop()
                self.after(0, self.deiconify)
                self.after(0, self.lift)

            def _run_tray_scan(icon, item):
                self.after(0, self._run_scan)

            def _quit_app(icon, item):
                icon.stop()
                self.after(0, self.destroy)

            menu = pystray.Menu(
                pystray.MenuItem("Open ShieldScan", _restore, default=True),
                pystray.MenuItem("Run Scan",        _run_tray_scan),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Quit",            _quit_app),
            )
            self._tray_icon = pystray.Icon(
                "ShieldScan", img, "ShieldScan", menu)

            # Minimise to tray on close instead of quitting
            self.protocol("WM_DELETE_WINDOW", self._minimise_to_tray)

            tray_thread = threading.Thread(
                target=self._tray_icon.run, daemon=True)
            tray_thread.start()
        except Exception:
            pass  # pystray / PIL not available — silent degradation

    def _minimise_to_tray(self):
        """Hide window to tray instead of closing."""
        if self._tray_icon:
            self.withdraw()
        else:
            self.destroy()

    # ══════════════════════════════════════════════════════════
    # Toast notifications
    # ══════════════════════════════════════════════════════════

    def _show_toast(self, msg: str, kind: str = "info"):
        """Slide-in toast from bottom-right, auto-dismiss after 4 s."""
        colors = {
            "info":    (C["blue"],   "ℹ"),
            "success": (C["green"],  "✓"),
            "warning": (C["yellow"], "⚠"),
            "error":   (C["red"],    "✗"),
        }
        color, icon = colors.get(kind, colors["info"])

        toast = tk.Toplevel(self)
        toast.wm_overrideredirect(True)
        toast.attributes("-topmost", True)
        toast.configure(bg=C["card2"])

        # Build content
        f = tk.Frame(toast, bg=C["card2"],
                     highlightbackground=color,
                     highlightthickness=1,
                     padx=14, pady=10)
        f.pack()
        tk.Label(f, text=icon, fg=color, bg=C["card2"],
                 font=("Segoe UI", 12)).pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(f, text=msg, fg=C["text"], bg=C["card2"],
                 font=("Segoe UI", 9), wraplength=280,
                 justify=tk.LEFT).pack(side=tk.LEFT)

        # Position: bottom-right of main window
        self.update_idletasks()
        toast.update_idletasks()
        tw = toast.winfo_reqwidth()
        th = toast.winfo_reqheight()
        wx = self.winfo_rootx() + self.winfo_width()
        wy = self.winfo_rooty() + self.winfo_height()
        tx = wx - tw - 16
        ty = wy - th - 40

        # Slide in: start 60 px below final position
        start_y = ty + 60
        toast.geometry(f"+{tx}+{start_y}")
        toast.deiconify()

        steps = 10
        step_px = 6

        def _slide(step=0):
            if step >= steps:
                return
            cur_y = start_y - step * step_px
            toast.geometry(f"+{tx}+{cur_y}")
            toast.after(16, _slide, step + 1)

        def _fade_out():
            try:
                toast.destroy()
            except Exception:
                pass

        _slide()
        toast.after(4000, _fade_out)

    # ══════════════════════════════════════════════════════════
    # Dashboard tab
    # ══════════════════════════════════════════════════════════

    def _build_dashboard_tab(self, parent):
        """Build the scaffold for the Dashboard tab."""
        # Header
        hrow = tk.Frame(parent, bg=C["surface"])
        hrow.pack(fill=tk.X)
        tk.Frame(hrow, bg=C["border"], height=1).pack(side=tk.BOTTOM, fill=tk.X)
        tk.Label(hrow, text="Dashboard",
                 fg=C["white"], bg=C["surface"],
                 font=("Segoe UI", 10, "bold"),
                 padx=20, pady=12).pack(side=tk.LEFT)
        ref_btn = tk.Button(hrow, text="↻  Refresh",
                            command=self._refresh_dashboard,
                            bg=C["surface"], fg=C["faint"],
                            activebackground=C["card"],
                            activeforeground=C["text"],
                            font=("Segoe UI", 8),
                            relief=tk.FLAT, bd=0, padx=10, pady=4,
                            cursor="hand2")
        ref_btn.pack(side=tk.RIGHT, padx=12, pady=8)
        ref_btn.bind("<Enter>", lambda _: ref_btn.configure(fg=C["text"], bg=C["card"]))
        ref_btn.bind("<Leave>", lambda _: ref_btn.configure(fg=C["faint"], bg=C["surface"]))

        # Scrollable body
        canvas = tk.Canvas(parent, bg=C["bg"], highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(parent, style="Slim.Vertical.TScrollbar",
                            orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._dash_inner = tk.Frame(canvas, bg=C["bg"])
        _wid = canvas.create_window((0, 0), window=self._dash_inner, anchor="nw")

        # Store refs for forced-width population
        self._dash_canvas = canvas
        self._dash_wid    = _wid

        def _on_dash_cfg(e, _c=canvas, _w=_wid):
            _c.itemconfig(_w, width=e.width)
        canvas.bind("<Configure>", _on_dash_cfg)

        def _on_dash_inner_cfg(e, _c=canvas):
            _c.configure(scrollregion=_c.bbox("all"))
        self._dash_inner.bind("<Configure>", _on_dash_inner_cfg)

        def _dw(e): canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        canvas.bind("<Enter>", lambda _: canvas.bind_all("<MouseWheel>", _dw))
        canvas.bind("<Leave>", lambda _: canvas.unbind_all("<MouseWheel>"))

    def _refresh_dashboard(self):  # noqa: C901
        """Populate the dashboard with comprehensive stats, charts and activity."""
        for w in self._dash_inner.winfo_children():
            w.destroy()

        pad = tk.Frame(self._dash_inner, bg=C["bg"])
        pad.pack(fill=tk.X, padx=28, pady=20)

        # ── Gather scan history data ────────────────────────────
        meta = _load_scan_meta()
        user_scans = [
            v for v in meta.values()
            if v.get("user") == self._current_user
        ]
        user_scans.sort(key=lambda x: x.get("ts", ""))

        total_scans  = len(user_scans)
        clean_count  = sum(1 for s in user_scans if s.get("verdict", "") == "CLEAN")
        threat_count = total_scans - clean_count
        avg_score    = (sum(s.get("score", 0) for s in user_scans) / total_scans
                        if total_scans else 0)

        # Time-based counts
        now_dt    = datetime.now()
        week_ago  = now_dt - timedelta(days=7)
        month_ago = now_dt - timedelta(days=30)
        scans_week = scans_month = 0
        for s in user_scans:
            try:
                ts_dt = datetime.fromisoformat(s.get("ts", ""))
                if ts_dt >= week_ago:
                    scans_week  += 1
                if ts_dt >= month_ago:
                    scans_month += 1
            except Exception:
                pass

        # ── Subtitle row ────────────────────────────────────────
        sub_row = tk.Frame(pad, bg=C["bg"])
        sub_row.pack(fill=tk.X, pady=(0, 12))
        tk.Label(sub_row,
                 text=f"Statistics for  {self._current_user}",
                 fg=C["text"], bg=C["bg"],
                 font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)
        tk.Label(sub_row,
                 text=f"Updated {now_dt.strftime('%H:%M')}",
                 fg=C["faint"], bg=C["bg"],
                 font=("Segoe UI", 8)).pack(side=tk.RIGHT)

        # ── Stat cards row ──────────────────────────────────────
        stat_row = tk.Frame(pad, bg=C["bg"])
        stat_row.pack(fill=tk.X, pady=(0, 8))
        for val, lbl, color in (
            (str(total_scans),   "Total Scans",    "blue"),
            (str(clean_count),   "Clean",          "green"),
            (str(threat_count),  "Threats Found",  "red"),
            (f"{avg_score:.0f}", "Avg Risk Score", "yellow"),
        ):
            co = tk.Frame(stat_row, bg=C[color])
            co.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=(0, 6))
            tk.Frame(co, bg=C[color], height=3).pack(fill=tk.X)
            cb = tk.Frame(co, bg=C["card"])
            cb.pack(fill=tk.BOTH, expand=True)
            ci = tk.Frame(cb, bg=C["card"])
            ci.pack(fill=tk.X, padx=16, pady=14)
            tk.Label(ci, text=lbl, fg=C["faint"], bg=C["card"],
                     font=("Segoe UI", 8)).pack(anchor="w")
            tk.Label(ci, text=val, fg=C[color], bg=C["card"],
                     font=("Consolas", 26, "bold")).pack(anchor="w", pady=(4, 0))

        # ── Quick Actions row ───────────────────────────────────
        tk.Label(pad, text="QUICK ACTIONS",
                 fg=C["muted"], bg=C["bg"],
                 font=("Segoe UI", 9, "bold"),
                 anchor="w").pack(fill=tk.X, pady=(16, 6))
        tk.Frame(pad, bg=C["border"], height=1).pack(fill=tk.X, pady=(0, 8))

        qa_btns = tk.Frame(pad, bg=C["bg"])
        qa_btns.pack(fill=tk.X, pady=(0, 18))

        def _quick_run():
            self._switch_tab("output")
            self.after(200, self._run_scan)

        def _quick_last_report():
            reports = sorted(
                [k for k, v in meta.items()
                 if v.get("user") == self._current_user
                 and k.endswith(".html")],
                key=lambda k: meta[k].get("ts", ""), reverse=True)
            if reports:
                path = os.path.join(_LOGS, reports[0])
                if os.path.exists(path):
                    os.startfile(path)
                    return
            messagebox.showinfo("No Report",
                                "No scan report found.\nRun a scan first.")

        for lbl, cmd, bg_c, fg_c in (
            ("▶  Run New Scan",      _quick_run,          C["green"], C["bg"]),
            ("📄  View Last Report", _quick_last_report,  C["card"],  C["text"]),
            ("⬇  Export CSV",       self._export_csv,    C["card"],  C["blue"]),
        ):
            b = tk.Button(qa_btns, text=lbl, command=cmd,
                          bg=bg_c, fg=fg_c,
                          activebackground=C["card2"],
                          activeforeground=C["white"],
                          font=("Segoe UI", 9),
                          relief=tk.FLAT, bd=0,
                          padx=14, pady=8, cursor="hand2")
            b.pack(side=tk.LEFT, padx=(0, 8))
            _obg, _ofg = bg_c, fg_c
            b.bind("<Enter>",
                   lambda _, _b=b: _b.configure(bg=C["card2"], fg=C["white"]))
            b.bind("<Leave>",
                   lambda _, _b=b, _bg=_obg, _fg=_ofg:
                   _b.configure(bg=_bg, fg=_fg))

        # ── ML model snapshot  +  scan activity (side by side) ─
        twin_row = tk.Frame(pad, bg=C["bg"])
        twin_row.pack(fill=tk.X, pady=(0, 20))

        mm: dict = {}
        if os.path.exists(_MODEL_META):
            try:
                with open(_MODEL_META, encoding="utf-8") as _f:
                    mm = json.load(_f)
            except Exception:
                pass

        # Left card — ML snapshot
        ml_outer = tk.Frame(twin_row, bg=C["purple"])
        ml_outer.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))
        tk.Frame(ml_outer, bg=C["purple"], height=3).pack(fill=tk.X)
        ml_body = tk.Frame(ml_outer, bg=C["card"])
        ml_body.pack(fill=tk.BOTH, expand=True)
        ml_i = tk.Frame(ml_body, bg=C["card"])
        ml_i.pack(fill=tk.X, padx=14, pady=12)
        tk.Label(ml_i, text="ML MODEL SNAPSHOT",
                 fg=C["muted"], bg=C["card"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 8))

        if mm:
            mv_row = tk.Frame(ml_i, bg=C["card"])
            mv_row.pack(fill=tk.X)
            for v_txt, l_txt, clr in (
                (f"{mm.get('cv_accuracy', 0):.1%}", "Accuracy", "green"),
                (f"{mm.get('f1_macro', 0):.3f}",    "F1 Macro", "blue"),
                (f"{mm.get('auc_roc', 0):.3f}"
                 if mm.get("auc_roc") else "N/A",    "AUC-ROC",  "purple"),
            ):
                mc = tk.Frame(mv_row, bg=C["card"])
                mc.pack(side=tk.LEFT, expand=True, padx=(0, 8))
                tk.Label(mc, text=v_txt, fg=C[clr], bg=C["card"],
                         font=("Consolas", 16, "bold")).pack(anchor="w")
                tk.Label(mc, text=l_txt, fg=C["faint"], bg=C["card"],
                         font=("Segoe UI", 7)).pack(anchor="w")

            trained_iso = mm.get("trained_at", "")
            _is_fresh   = False
            trained_fmt = "Unknown"
            try:
                _td = datetime.fromisoformat(trained_iso)
                trained_fmt = _td.strftime("%d %b %Y")
                _is_fresh = (now_dt - _td).days <= 30
            except Exception:
                pass
            fresh_clr = "green" if _is_fresh else "yellow"
            fresh_txt = (f"✓ Trained {trained_fmt}"
                         if _is_fresh else "⚠ Stale — retrain recommended")
            tk.Label(ml_i, text=fresh_txt, fg=C[fresh_clr], bg=C["card"],
                     font=("Segoe UI", 8)).pack(anchor="w", pady=(8, 0))

            def _go_model():
                self._switch_tab("model")
            lnk = tk.Label(ml_i, text="→ Full Model Details",
                           fg=C["blue"], bg=C["card"],
                           font=("Segoe UI", 8, "underline"),
                           cursor="hand2")
            lnk.pack(anchor="w", pady=(4, 0))
            lnk.bind("<Button-1>", lambda _: _go_model())
        else:
            tk.Label(ml_i, text="Model not yet trained.",
                     fg=C["muted"], bg=C["card"],
                     font=("Segoe UI", 9)).pack(anchor="w")
            _bt = tk.Button(ml_i, text="  Train Now  ",
                            command=lambda: self._update_ml(False),
                            bg=C["green"], fg=C["bg"],
                            font=("Segoe UI", 8, "bold"),
                            relief=tk.FLAT, bd=0,
                            padx=10, pady=5, cursor="hand2")
            _bt.pack(anchor="w", pady=(8, 0))

        # Right card — scan activity
        ta_outer = tk.Frame(twin_row, bg=C["blue"])
        ta_outer.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Frame(ta_outer, bg=C["blue"], height=3).pack(fill=tk.X)
        ta_body = tk.Frame(ta_outer, bg=C["card"])
        ta_body.pack(fill=tk.BOTH, expand=True)
        ta_i = tk.Frame(ta_body, bg=C["card"])
        ta_i.pack(fill=tk.X, padx=14, pady=12)
        tk.Label(ta_i, text="SCAN ACTIVITY",
                 fg=C["muted"], bg=C["card"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 8))

        threat_rate_txt = (f"{threat_count / total_scans:.0%}"
                           if total_scans else "0%")
        threat_rate_clr = "red" if threat_count else "green"
        for v_txt, l_txt, clr in (
            (str(scans_week),    "Scans this week",  "blue"),
            (str(scans_month),   "Scans this month", "blue"),
            (str(total_scans),   "Total scans ever", "faint"),
            (threat_rate_txt,    "Threat rate",      threat_rate_clr),
        ):
            tr = tk.Frame(ta_i, bg=C["card"])
            tr.pack(fill=tk.X, pady=3)
            tk.Label(tr, text=v_txt, fg=C[clr], bg=C["card"],
                     font=("Consolas", 14, "bold"), width=6,
                     anchor="w").pack(side=tk.LEFT)
            tk.Label(tr, text=l_txt, fg=C["faint"], bg=C["card"],
                     font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(6, 0))

        # ── Risk score history chart ────────────────────────────
        tk.Label(pad, text="RISK SCORE HISTORY",
                 fg=C["muted"], bg=C["bg"],
                 font=("Segoe UI", 9, "bold"),
                 anchor="w").pack(fill=tk.X, pady=(0, 6))
        tk.Frame(pad, bg=C["border"], height=1).pack(fill=tk.X, pady=(0, 8))

        chart_h = 180
        chart = tk.Canvas(pad, bg=C["card"], height=chart_h,
                          highlightthickness=0, bd=0)
        chart.pack(fill=tk.X)

        def _draw_chart(event=None):
            chart.delete("all")
            w = chart.winfo_width()
            if w < 10:
                return

            scores = [s.get("score", 0) for s in user_scans]
            if len(scores) < 2:
                chart.create_rectangle(0, 0, w, chart_h,
                                       fill=C["card"], outline="")
                chart.create_text(w // 2, chart_h // 2 - 12,
                                  text="📊",
                                  fill=C["border"],
                                  font=("Segoe UI", 22))
                chart.create_text(w // 2, chart_h // 2 + 16,
                                  text="Run 2+ scans to see the risk-score trend.",
                                  fill=C["faint"],
                                  font=("Segoe UI", 9),
                                  justify="center")
                return

            px_l, px_r, py_t, py_b = 46, 20, 16, 34
            bw = w - px_l - px_r
            bh = chart_h - py_t - py_b
            n  = len(scores)

            chart.create_rectangle(px_l, py_t, w - px_r, py_t + bh,
                                   fill=C["card"], outline="")
            for tick in (0, 25, 50, 75, 100):
                y = py_t + bh - round(tick / 100 * bh)
                chart.create_line(px_l, y, w - px_r, y,
                                  fill=C["border"], dash=(3, 5))
                chart.create_text(px_l - 6, y, text=str(tick),
                                  anchor="e", fill=C["faint"],
                                  font=("Segoe UI", 7))
            chart.create_line(px_l, py_t + bh, w - px_r, py_t + bh,
                              fill=C["border"], width=1)

            pts = []
            for i, sc in enumerate(scores):
                x = px_l + round(i / max(n - 1, 1) * bw)
                y = py_t + bh - round(min(sc, 100) / 100 * bh)
                pts.append((x, y))

            step = max(1, n // 8)
            for i in range(0, n, step):
                chart.create_text(pts[i][0], py_t + bh + 10,
                                  text=f"#{i+1}",
                                  anchor="n", fill=C["faint"],
                                  font=("Segoe UI", 7))

            poly = [pts[0][0], py_t + bh]
            for _px, _py in pts:
                poly += [_px, _py]
            poly += [pts[-1][0], py_t + bh]
            if len(poly) >= 6:
                chart.create_polygon(poly, fill=C["z_blue"], outline="")

            flat = [c for pt in pts for c in pt]
            if len(flat) >= 4:
                chart.create_line(*flat, fill=C["blue"], width=2, smooth=True)

            for i, (x, y) in enumerate(pts):
                sc  = scores[i]
                clr = (C["red"]    if sc >= 61 else
                       C["yellow"] if sc >= 41 else
                       C["blue"]   if sc >= 16 else C["green"])
                chart.create_oval(x - 4, y - 4, x + 4, y + 4,
                                  fill=clr, outline=C["bg"], width=1)

        chart.bind("<Configure>", _draw_chart)
        pad.after(80, _draw_chart)

        # ── Recent Scans list ───────────────────────────────────
        if user_scans:
            tk.Label(pad, text="RECENT SCANS",
                     fg=C["muted"], bg=C["bg"],
                     font=("Segoe UI", 9, "bold"),
                     anchor="w").pack(fill=tk.X, pady=(20, 6))
            tk.Frame(pad, bg=C["border"], height=1).pack(fill=tk.X, pady=(0, 8))

            recent = list(reversed(user_scans))[:10]
            for entry in recent:
                vd  = entry.get("verdict", "UNKNOWN")
                sc  = entry.get("score",   0)
                try:
                    ts_fmt = datetime.fromisoformat(
                        entry.get("ts", "")).strftime("%d %b %Y  %H:%M")
                except Exception:
                    ts_fmt = entry.get("ts", "—") or "—"
                vclr = _VERDICT_COLOR.get(vd, C["faint"])

                sr = tk.Frame(pad, bg=C["surface"])
                sr.pack(fill=tk.X, pady=2)
                tk.Frame(sr, bg=vclr, width=3).pack(side=tk.LEFT, fill=tk.Y)

                sb = tk.Frame(sr, bg=C["surface"])
                sb.pack(side=tk.LEFT, fill=tk.X, expand=True,
                        padx=10, pady=7)

                sr_top = tk.Frame(sb, bg=C["surface"])
                sr_top.pack(fill=tk.X)
                tk.Label(sr_top, text=ts_fmt,
                         fg=C["text"], bg=C["surface"],
                         font=("Segoe UI", 8)).pack(side=tk.LEFT)
                pill_fg = C["bg"]   if vd not in ("UNKNOWN", "") else C["muted"]
                pill_bg = vclr      if vd not in ("UNKNOWN", "") else C["card2"]
                tk.Label(sr_top, text=f"  {vd}  ",
                         fg=pill_fg, bg=pill_bg,
                         font=("Segoe UI", 7, "bold"), padx=2).pack(side=tk.RIGHT)

                sr_bot = tk.Frame(sb, bg=C["surface"])
                sr_bot.pack(fill=tk.X, pady=(4, 0))
                tk.Label(sr_bot, text="Risk",
                         fg=C["faint"], bg=C["surface"],
                         font=("Segoe UI", 7)).pack(side=tk.LEFT)
                sc_bar = tk.Canvas(sr_bot, bg=C["card2"], height=5,
                                   highlightthickness=0, bd=0)
                sc_bar.pack(side=tk.LEFT, fill=tk.X,
                            expand=True, padx=(6, 6))
                _pv = min(sc / 100, 1.0)
                def _dsb(e=None, _b=sc_bar, _c=vclr, _p=_pv):
                    _b.delete("all")
                    bw2 = _b.winfo_width()
                    if bw2 < 2:
                        return
                    fw = max(0, round(_p * bw2))
                    if fw:
                        _b.create_rectangle(0, 0, fw, 5,
                                            fill=_c, outline="")
                sc_bar.bind("<Configure>", _dsb)
                sc_bar.after(20, _dsb)
                tk.Label(sr_bot, text=f"{sc}/100",
                         fg=vclr, bg=C["surface"],
                         font=("Consolas", 8, "bold")).pack(side=tk.RIGHT)

        # ── Highest-risk scan highlight ─────────────────────────
        if user_scans and threat_count > 0:
            worst       = max(user_scans, key=lambda x: x.get("score", 0))
            worst_score = worst.get("score", 0)
            if worst_score >= 16:
                worst_vd  = worst.get("verdict", "UNKNOWN")
                worst_clr = _VERDICT_COLOR.get(worst_vd, C["red"])
                try:
                    worst_ts = datetime.fromisoformat(
                        worst.get("ts", "")).strftime("%d %b %Y  %H:%M")
                except Exception:
                    worst_ts = worst.get("ts", "—") or "—"

                tk.Label(pad, text="HIGHEST RISK SCAN",
                         fg=C["muted"], bg=C["bg"],
                         font=("Segoe UI", 9, "bold"),
                         anchor="w").pack(fill=tk.X, pady=(20, 6))
                tk.Frame(pad, bg=C["border"], height=1).pack(fill=tk.X,
                                                             pady=(0, 8))

                hr_o = tk.Frame(pad, bg=worst_clr)
                hr_o.pack(fill=tk.X)
                tk.Frame(hr_o, bg=worst_clr, height=3).pack(fill=tk.X)
                hr_b = tk.Frame(hr_o, bg=C["card"])
                hr_b.pack(fill=tk.X)
                hr_i = tk.Frame(hr_b, bg=C["card"])
                hr_i.pack(fill=tk.X, padx=16, pady=12)

                hr_top = tk.Frame(hr_i, bg=C["card"])
                hr_top.pack(fill=tk.X)
                tk.Label(hr_top,
                         text=f"⚠  Score  {worst_score} / 100",
                         fg=worst_clr, bg=C["card"],
                         font=("Consolas", 18, "bold")).pack(side=tk.LEFT)
                tk.Label(hr_top,
                         text=f"  {worst_vd}  ",
                         fg=C["bg"], bg=worst_clr,
                         font=("Segoe UI", 8, "bold"),
                         padx=4).pack(side=tk.LEFT, padx=(12, 0))
                tk.Label(hr_i, text=f"Occurred:  {worst_ts}",
                         fg=C["faint"], bg=C["card"],
                         font=("Segoe UI", 8)).pack(anchor="w", pady=(4, 0))
                tk.Label(hr_i,
                         text="Review the full report in the History tab for "
                              "detailed findings and remediation steps.",
                         fg=C["muted"], bg=C["card"],
                         font=("Segoe UI", 8),
                         wraplength=540,
                         justify=tk.LEFT).pack(anchor="w", pady=(2, 0))

        # ── Verdict breakdown bars ──────────────────────────────
        if user_scans:
            tk.Label(pad, text="VERDICT BREAKDOWN",
                     fg=C["muted"], bg=C["bg"],
                     font=("Segoe UI", 9, "bold"),
                     anchor="w").pack(fill=tk.X, pady=(20, 6))
            tk.Frame(pad, bg=C["border"], height=1).pack(fill=tk.X, pady=(0, 8))

            verdict_counts: dict[str, int] = {}
            for s in user_scans:
                v = s.get("verdict", "UNKNOWN")
                verdict_counts[v] = verdict_counts.get(v, 0) + 1

            for verdict_name, cnt in sorted(verdict_counts.items(),
                                            key=lambda x: -x[1]):
                row = tk.Frame(pad, bg=C["bg"])
                row.pack(fill=tk.X, pady=4)
                vclr2 = _VERDICT_COLOR.get(verdict_name, C["faint"])
                tk.Label(row, text=f"  {verdict_name}",
                         fg=vclr2, bg=C["bg"],
                         font=("Segoe UI", 9, "bold"),
                         width=14, anchor="w").pack(side=tk.LEFT)
                pct = cnt / total_scans if total_scans else 0
                vbar = tk.Canvas(row, bg=C["card2"], height=12,
                                 highlightthickness=0, bd=0)
                vbar.pack(side=tk.LEFT, fill=tk.X,
                          expand=True, padx=(8, 8))
                def _dvb(e=None, _b=vbar, _c=vclr2, _p=pct):
                    _b.delete("all")
                    bw3 = _b.winfo_width()
                    if bw3 < 2:
                        return
                    fw = max(0, round(_p * bw3))
                    if fw:
                        _b.create_rectangle(0, 0, fw, 12, fill=_c, outline="")
                vbar.bind("<Configure>", _dvb)
                vbar.after(20, _dvb)
                tk.Label(row, text=f"{cnt}  ({pct:.0%})",
                         fg=C["muted"], bg=C["bg"],
                         font=("Consolas", 8)).pack(side=tk.RIGHT)

        # ── No-data placeholder ─────────────────────────────────
        if not user_scans:
            no_data = tk.Frame(pad, bg=C["card"])
            no_data.pack(fill=tk.X, pady=(10, 0))
            tk.Frame(no_data, bg=C["blue"], height=3).pack(fill=tk.X)
            nd_i = tk.Frame(no_data, bg=C["card"])
            nd_i.pack(fill=tk.X, padx=20, pady=18)
            tk.Label(nd_i, text="No scan history yet.",
                     fg=C["blue"], bg=C["card"],
                     font=("Segoe UI", 11, "bold")).pack(anchor="w")
            tk.Label(nd_i,
                     text="Run your first scan to populate the dashboard with "
                          "metrics, charts and activity history.",
                     fg=C["muted"], bg=C["card"],
                     font=("Segoe UI", 9),
                     wraplength=600, justify=tk.LEFT).pack(anchor="w", pady=(6, 0))
            _rs = tk.Button(nd_i, text="  ▶  Run Scan Now  ",
                            command=lambda: (self._switch_tab("output"),
                                            self.after(200, self._run_scan)),
                            bg=C["green"], fg=C["bg"],
                            activebackground="#4ac760",
                            font=("Segoe UI", 10, "bold"),
                            relief=tk.FLAT, bd=0,
                            padx=16, pady=10, cursor="hand2")
            _rs.pack(anchor="w", pady=(14, 0))

        # ── Footer: export button ───────────────────────────────
        foot = tk.Frame(pad, bg=C["bg"])
        foot.pack(fill=tk.X, pady=(24, 0))
        export_btn = tk.Button(foot, text="⬇  Export Findings to CSV",
                               command=self._export_csv,
                               bg=C["card"], fg=C["blue"],
                               activebackground=C["card2"],
                               activeforeground=C["white"],
                               font=("Segoe UI", 9),
                               relief=tk.FLAT, bd=0,
                               padx=12, pady=7, cursor="hand2")
        export_btn.pack(side=tk.LEFT)
        export_btn.bind("<Enter>", lambda _: export_btn.configure(
            bg=C["card2"], fg=C["white"]))
        export_btn.bind("<Leave>", lambda _: export_btn.configure(
            bg=C["card"], fg=C["blue"]))
        Tooltip(export_btn, "Save the current scan output as a CSV file.")

    # ══════════════════════════════════════════════════════════
    # Export to CSV
    # ══════════════════════════════════════════════════════════

    def _export_csv(self):
        """Export findings from the output text area to a CSV file."""
        content = ""
        try:
            content = self._txt.get("1.0", tk.END)
        except Exception:
            pass
        if not content.strip():
            messagebox.showinfo("No Output",
                                "No scan output to export.\n\n"
                                "Run a scan first, then export.")
            return

        default_name = (f"shieldscan_findings_"
                        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        out = filedialog.asksaveasfilename(
            title="Export Findings as CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=default_name,
        )
        if not out:
            return

        import csv
        rows = []
        severity_re = re.compile(r"\[(HIG|MED|LOW|OK|!!)\]", re.I)
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            m = severity_re.search(stripped)
            sev = m.group(1).upper() if m else ""
            clean_line = re.sub(r"\[.*?\]\s*", "", stripped).strip()
            if clean_line:
                rows.append({
                    "severity": sev,
                    "finding":  clean_line,
                    "user":     self._current_user,
                    "exported": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                })

        try:
            with open(out, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=["severity", "finding", "user", "exported"])
                writer.writeheader()
                writer.writerows(rows)
            self._show_toast(
                f"Exported {len(rows)} findings → {os.path.basename(out)}",
                "success")
            self._sv_status.set(f"CSV exported: {os.path.basename(out)}")
            if messagebox.askyesno("CSV Exported",
                                   f"Saved {len(rows)} rows to:\n{out}\n\nOpen now?"):
                os.startfile(out)
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))

    # ══════════════════════════════════════════════════════════
    # History comparison
    # ══════════════════════════════════════════════════════════

    def _compare_selected(self):
        """Open a side-by-side diff dialog for two selected reports."""
        selected = [p for p, v in self._hist_selected.items() if v.get()]
        if len(selected) != 2:
            messagebox.showinfo("Select Reports",
                                "Please check exactly 2 reports to compare.")
            return

        def _parse_report(path: str) -> dict:
            """Extract key fields from a report HTML."""
            out = {"path": path, "score": 0, "verdict": "—",
                   "findings": [], "ts": "—"}
            try:
                fname = os.path.basename(path)
                ts_part = fname.replace("report_", "").replace(".html", "")
                dt = datetime.strptime(ts_part, "%Y%m%d_%H%M%S")
                out["ts"] = dt.strftime("%d %b %Y  %H:%M:%S")
            except Exception:
                pass
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    html = f.read(20000)
                ms = re.search(r'class="risk-score"[^>]*>(\d+)', html)
                if ms:
                    out["score"] = int(ms.group(1))
                mv = re.search(r'<div class="verdict">(.*?)</div>', html, re.S)
                if mv:
                    raw = re.sub(r"<[^>]+>", "", mv.group(1)).strip()
                    for kw in ("COMPROMISED", "SUSPICIOUS", "LOW RISK", "CLEAN"):
                        if kw in raw.upper():
                            out["verdict"] = kw
                            break
                # Extract finding bullets
                blocks = re.findall(
                    r'class="[^"]*finding[^"]*"[^>]*>(.*?)</(?:div|tr)>',
                    html, re.S | re.I)
                for blk in blocks[:40]:
                    t = re.sub(r'<[^>]+>', ' ', blk)
                    t = re.sub(r'\s+', ' ', t).strip()
                    if t:
                        out["findings"].append(t[:200])
            except Exception:
                pass
            return out

        a, b = _parse_report(selected[0]), _parse_report(selected[1])

        # ── Dialog ────────────────────────────────────────────
        dlg = tk.Toplevel(self)
        dlg.title("Compare Scans")
        dlg.configure(bg=C["surface"])
        dlg.resizable(True, True)
        dlg.grab_set()
        dlg.transient(self)
        dlg.geometry("960x620")

        # Header
        hdr = tk.Frame(dlg, bg=C["card"])
        hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg=C["border"], height=1).pack(side=tk.BOTTOM, fill=tk.X)
        tk.Label(hdr, text="⇄  Side-by-Side Scan Comparison",
                 fg=C["white"], bg=C["card"],
                 font=("Segoe UI", 11, "bold"),
                 padx=20, pady=12).pack(side=tk.LEFT)

        # Two columns
        cols = tk.Frame(dlg, bg=C["bg"])
        cols.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)
        cols.columnconfigure(0, weight=1)
        cols.columnconfigure(1, weight=1)

        def _col(parent, data: dict, col: int):
            vclr = _VERDICT_COLOR.get(data["verdict"], C["faint"])
            frame = tk.Frame(parent, bg=C["card2"])
            frame.grid(row=0, column=col, sticky="nsew",
                       padx=(0, 8) if col == 0 else (8, 0))

            # Title
            tk.Label(frame, text=data["ts"],
                     fg=C["white"], bg=C["card2"],
                     font=("Segoe UI", 9, "bold"),
                     padx=14, pady=8).pack(anchor="w")
            tk.Frame(frame, bg=C["border"], height=1).pack(fill=tk.X)

            # Score + verdict
            sv_row = tk.Frame(frame, bg=C["card2"])
            sv_row.pack(fill=tk.X, padx=14, pady=10)
            tk.Label(sv_row, text=str(data["score"]),
                     fg=vclr, bg=C["card2"],
                     font=("Consolas", 32, "bold")).pack(side=tk.LEFT)
            tk.Label(sv_row, text=" / 100",
                     fg=C["faint"], bg=C["card2"],
                     font=("Consolas", 10)).pack(side=tk.LEFT, pady=(14, 0))
            tk.Label(sv_row, text=f"  {data['verdict']}",
                     fg=vclr, bg=C["card2"],
                     font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, pady=(12, 0))

            # Findings list
            tk.Label(frame,
                     text=f"Findings: {len(data['findings'])}",
                     fg=C["muted"], bg=C["card2"],
                     font=("Segoe UI", 8), padx=14).pack(anchor="w")

            # Scrollable findings
            list_canvas = tk.Canvas(frame, bg=C["card"], height=360,
                                    highlightthickness=0, bd=0)
            lvs = ttk.Scrollbar(frame, style="Slim.Vertical.TScrollbar",
                                orient=tk.VERTICAL, command=list_canvas.yview)
            list_canvas.configure(yscrollcommand=lvs.set)
            lvs.pack(side=tk.RIGHT, fill=tk.Y)
            list_canvas.pack(fill=tk.BOTH, expand=True, padx=14, pady=(4, 14))

            lf = tk.Frame(list_canvas, bg=C["card"])
            _lw = list_canvas.create_window((0, 0), window=lf, anchor="nw")
            list_canvas.bind("<Configure>",
                             lambda e: list_canvas.itemconfig(_lw, width=e.width))
            lf.bind("<Configure>",
                    lambda e: list_canvas.configure(
                        scrollregion=list_canvas.bbox("all")))

            if data["findings"]:
                for fi in data["findings"]:
                    tk.Label(lf, text=f"  • {fi}",
                             fg=C["text"], bg=C["card"],
                             font=("Segoe UI", 8), anchor="w",
                             wraplength=380, justify=tk.LEFT,
                             pady=3).pack(fill=tk.X)
            else:
                tk.Label(lf, text="  No findings extracted.",
                         fg=C["faint"], bg=C["card"],
                         font=("Segoe UI", 8)).pack(anchor="w", pady=10)

        _col(cols, a, 0)
        _col(cols, b, 1)

        # Delta summary
        delta = b["score"] - a["score"]
        delta_txt = (f"▲ +{delta}" if delta > 0
                     else f"▼ {delta}" if delta < 0
                     else "— No change")
        delta_clr = (C["red"] if delta > 0
                     else C["green"] if delta < 0
                     else C["faint"])
        foot = tk.Frame(dlg, bg=C["surface"])
        foot.pack(fill=tk.X, padx=20, pady=12)
        tk.Label(foot,
                 text=f"Risk score delta:  {delta_txt}",
                 fg=delta_clr, bg=C["surface"],
                 font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        tk.Button(foot, text="  Close  ", command=dlg.destroy,
                  bg=C["green"], fg=C["bg"],
                  activebackground="#4ac760",
                  font=("Segoe UI", 9, "bold"),
                  relief=tk.FLAT, bd=0,
                  padx=14, pady=7, cursor="hand2").pack(side=tk.RIGHT)

    # ══════════════════════════════════════════════════════════
    # Settings dialog
    # ══════════════════════════════════════════════════════════

    def _settings_dialog(self):
        dlg = tk.Toplevel(self)
        dlg.title("Settings")
        dlg.configure(bg=C["surface"])
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.transient(self)
        dlg.geometry("640x480")

        # Header
        hdr = tk.Frame(dlg, bg=C["card"])
        hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg=C["border"], height=1).pack(side=tk.BOTTOM, fill=tk.X)
        tk.Label(hdr, text="⚙  Settings",
                 fg=C["white"], bg=C["card"],
                 font=("Segoe UI", 11, "bold"),
                 padx=20, pady=12).pack(side=tk.LEFT)

        # Sidebar + content area
        body = tk.Frame(dlg, bg=C["bg"])
        body.pack(fill=tk.BOTH, expand=True)

        sidebar = tk.Frame(body, bg=C["surface"], width=160)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)
        tk.Frame(body, bg=C["border"], width=1).pack(side=tk.LEFT, fill=tk.Y)

        content = tk.Frame(body, bg=C["bg"])
        content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Active tab state
        _active_tab: list = ["general"]
        _tab_btns: dict[str, tk.Button] = {}
        _tab_frames: dict[str, tk.Frame] = {}

        def _switch_settings(tab: str):
            _active_tab[0] = tab
            for t, f in _tab_frames.items():
                f.pack_forget()
            _tab_frames[tab].pack(fill=tk.BOTH, expand=True, padx=24, pady=18)
            for t, b in _tab_btns.items():
                b.configure(
                    fg=C["white"] if t == tab else C["muted"],
                    bg=C["card"] if t == tab else C["surface"],
                )

        def _side_btn(key: str, label: str):
            b = tk.Button(sidebar, text=label, command=lambda: _switch_settings(key),
                          bg=C["surface"], fg=C["muted"],
                          activebackground=C["card"],
                          activeforeground=C["white"],
                          font=("Segoe UI", 9),
                          relief=tk.FLAT, bd=0,
                          padx=16, pady=10, anchor="w", cursor="hand2")
            b.pack(fill=tk.X, pady=1)
            b.bind("<Enter>", lambda _: b.configure(
                fg=C["white"] if _active_tab[0] == key else C["text"],
                bg=C["card"]))
            b.bind("<Leave>", lambda _: b.configure(
                fg=C["white"] if _active_tab[0] == key else C["muted"],
                bg=C["card"] if _active_tab[0] == key else C["surface"]))
            _tab_btns[key] = b

        def _make_frame(key: str) -> tk.Frame:
            f = tk.Frame(content, bg=C["bg"])
            _tab_frames[key] = f
            return f

        def _section_lbl(parent, text: str):
            tk.Label(parent, text=text, fg=C["muted"], bg=C["bg"],
                     font=("Segoe UI", 7, "bold"), anchor="w").pack(
                         fill=tk.X, pady=(12, 4))
            tk.Frame(parent, bg=C["border"], height=1).pack(fill=tk.X)

        def _toggle_row(parent, label: str, var: tk.BooleanVar, tip: str = ""):
            row = tk.Frame(parent, bg=C["card"], cursor="hand2")
            row.pack(fill=tk.X, pady=3)
            box = tk.Label(row, text="  ", width=2, bg=C["card2"],
                           font=("Consolas", 8))
            box.pack(side=tk.LEFT, padx=(12, 0), pady=8)
            lbl = tk.Label(row, text=label, fg=C["muted"], bg=C["card"],
                           font=("Segoe UI", 9))
            lbl.pack(side=tk.LEFT, padx=(8, 0))
            if tip:
                Tooltip(row, tip)

            def _ref(*_):
                box.configure(bg=C["green"] if var.get() else C["card2"],
                              text="✓" if var.get() else "  ",
                              fg=C["bg"] if var.get() else C["card2"])
                lbl.configure(fg=C["text"] if var.get() else C["muted"])
            var.trace_add("write", _ref); _ref()
            for w in (row, box, lbl):
                w.bind("<Button-1>", lambda _: var.set(not var.get()))

        # ── Load current config ────────────────────────────────
        cfg = _load_app_cfg()
        sv_toast    = tk.BooleanVar(value=bool(cfg.get("toast_notifications", True)))
        sv_tray     = tk.BooleanVar(value=bool(cfg.get("start_minimised", False)))
        sv_autoupd  = tk.BooleanVar(value=bool(cfg.get("auto_update_ml", False)))
        sv_dark_bar = tk.BooleanVar(value=bool(cfg.get("dark_titlebar", True)))

        # ── GENERAL tab ────────────────────────────────────────
        _side_btn("general", "  General")
        gf = _make_frame("general")
        _section_lbl(gf, "BEHAVIOUR")
        _toggle_row(gf, "Start minimised to system tray",
                    sv_tray,
                    "Launch ShieldScan hidden in the tray instead of showing the window.")
        _toggle_row(gf, "Dark title bar",
                    sv_dark_bar,
                    "Apply Windows 11 dark-mode styling to the title bar.")
        _section_lbl(gf, "ML MODEL")
        _toggle_row(gf, "Auto-update ML model on startup",
                    sv_autoupd,
                    "Re-train the classifier each time ShieldScan launches.")

        # ── NOTIFICATIONS tab ──────────────────────────────────
        _side_btn("notifications", "  Notifications")
        nf = _make_frame("notifications")
        _section_lbl(nf, "TOAST ALERTS")
        _toggle_row(nf, "Show toast notifications",
                    sv_toast,
                    "Slide-in pop-up messages after scan completes or export finishes.")
        tk.Label(nf,
                 text="Toast alerts appear in the bottom-right corner of the window\n"
                      "and dismiss automatically after 4 seconds.",
                 fg=C["faint"], bg=C["bg"],
                 font=("Segoe UI", 8), justify=tk.LEFT).pack(
                     anchor="w", pady=(6, 0))
        tk.Button(nf, text="  Preview Toast  ",
                  command=lambda: self._show_toast(
                      "This is a test notification!", "info"),
                  bg=C["card"], fg=C["blue"],
                  activebackground=C["card2"],
                  activeforeground=C["white"],
                  font=("Segoe UI", 8),
                  relief=tk.FLAT, bd=0,
                  padx=12, pady=5, cursor="hand2").pack(anchor="w", pady=(10, 0))

        # ── APPEARANCE tab ─────────────────────────────────────
        _side_btn("appearance", "  Appearance")
        af = _make_frame("appearance")
        _section_lbl(af, "COLOUR THEME")
        current_theme = _current_theme_name()
        sv_theme = tk.StringVar(value=current_theme)

        theme_grid = tk.Frame(af, bg=C["bg"])
        theme_grid.pack(fill=tk.X, pady=(6, 0))
        for i, (tname, tdata) in enumerate(_THEMES.items()):
            dot_clr = _THEME_DOTS[tname]
            cell = tk.Frame(theme_grid, bg=C["card"], padx=14, pady=10,
                            cursor="hand2")
            cell.grid(row=0, column=i, padx=(0, 8), sticky="nsew")
            theme_grid.columnconfigure(i, weight=1)
            tk.Label(cell, text="⬤", fg=dot_clr, bg=C["card"],
                     font=("Segoe UI", 20)).pack()
            tk.Label(cell, text=tname,
                     fg=C["white"] if tname == current_theme else C["muted"],
                     bg=C["card"], font=("Segoe UI", 8)).pack()
            if tname == current_theme:
                tk.Frame(cell, bg=dot_clr, height=2).pack(fill=tk.X, pady=(4, 0))

            def _pick(n=tname):
                sv_theme.set(n)
                # Apply immediately
                cfg2 = _load_app_cfg()
                cfg2["theme"] = n
                _save_app_cfg(cfg2)
                dlg.destroy()
                global C, _VERDICT_COLOR
                C = dict(_THEMES[n])
                _VERDICT_COLOR = _build_verdict_color()
                self._restart_requested = True
                self.destroy()

            for w in (cell,) + tuple(cell.winfo_children()):
                w.bind("<Button-1>", lambda _, fn=_pick: fn())

        # ── ACCOUNT tab ────────────────────────────────────────
        _side_btn("account", "  Account")
        acf = _make_frame("account")
        _section_lbl(acf, "SIGNED-IN USER")

        info_card = tk.Frame(acf, bg=C["card2"], padx=16, pady=14)
        info_card.pack(fill=tk.X, pady=(6, 0))
        initials = (self._current_user[:2]).upper()
        tk.Label(info_card, text=initials,
                 fg=C["accent"], bg=C["card2"],
                 font=("Consolas", 22, "bold")).pack(side=tk.LEFT, padx=(0, 14))
        uinfo = tk.Frame(info_card, bg=C["card2"])
        uinfo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(uinfo, text=self._current_user,
                 fg=C["white"], bg=C["card2"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w")
        tk.Label(uinfo, text=self._current_email or "No email registered",
                 fg=C["faint"], bg=C["card2"],
                 font=("Segoe UI", 8)).pack(anchor="w")

        _section_lbl(acf, "ACTIONS")
        for lbl, cmd in (
            ("Configure Email Settings", self._email_settings_dialog),
            ("Logout", self._logout),
        ):
            b = tk.Button(acf, text=lbl, command=lambda fn=cmd: (dlg.destroy(), fn()),
                          bg=C["card"], fg=C["muted"],
                          activebackground=C["card2"],
                          activeforeground=C["text"],
                          font=("Segoe UI", 9),
                          relief=tk.FLAT, bd=0,
                          padx=12, pady=7, anchor="w", cursor="hand2")
            b.pack(fill=tk.X, pady=2)
            b.bind("<Enter>", lambda _, w=b: w.configure(fg=C["text"], bg=C["card2"]))
            b.bind("<Leave>", lambda _, w=b: w.configure(fg=C["muted"], bg=C["card"]))

        # Bottom save button
        foot = tk.Frame(dlg, bg=C["surface"])
        foot.pack(fill=tk.X, side=tk.BOTTOM, padx=20, pady=14)

        def _save_settings():
            cfg_new = _load_app_cfg()
            cfg_new["toast_notifications"] = sv_toast.get()
            cfg_new["start_minimised"]     = sv_tray.get()
            cfg_new["auto_update_ml"]      = sv_autoupd.get()
            cfg_new["dark_titlebar"]       = sv_dark_bar.get()
            _save_app_cfg(cfg_new)
            self._show_toast("Settings saved.", "success")
            dlg.destroy()

        tk.Button(foot, text="Cancel", command=dlg.destroy,
                  bg=C["surface"], fg=C["muted"],
                  activebackground=C["card"],
                  activeforeground=C["text"],
                  font=("Segoe UI", 9), relief=tk.FLAT, bd=0,
                  padx=14, pady=6, cursor="hand2").pack(side=tk.RIGHT, padx=(8, 0))
        tk.Button(foot, text="Save Settings", command=_save_settings,
                  bg=C["green"], fg=C["bg"],
                  activebackground="#4ac760",
                  font=("Segoe UI", 9, "bold"),
                  relief=tk.FLAT, bd=0,
                  padx=14, pady=6, cursor="hand2").pack(side=tk.RIGHT)

        _switch_settings("general")

    # ── Logout ────────────────────────────────────────────────

    def _logout(self):
        if self._scanning:
            messagebox.showwarning(
                "Scan Running",
                "A scan is currently running.\n\n"
                "Please stop the scan before logging out.")
            return
        if messagebox.askyesno(
            "Logout",
            f"Log out of '{self._current_user}'?\n\n"
            "You will be returned to the login screen."
        ):
            self._logout_requested = True
            self.destroy()

    # ── Status bar ────────────────────────────────────────────

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=C["surface"], height=28)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)
        tk.Frame(bar, bg=C["border"], height=1).pack(
            side=tk.TOP, fill=tk.X)
        self._status_dot = tk.Label(bar, text="●",
                                     fg=C["faint"], bg=C["surface"],
                                     font=("Segoe UI", 9), padx=10)
        self._status_dot.pack(side=tk.LEFT)
        tk.Label(bar, textvariable=self._sv_status,
                 fg=C["muted"], bg=C["surface"],
                 font=("Segoe UI", 8)).pack(side=tk.LEFT)
        right_bar = tk.Frame(bar, bg=C["surface"])
        right_bar.pack(side=tk.RIGHT)
        tk.Label(right_bar,
                 text=f"● {self._current_user}",
                 fg=C["green"], bg=C["surface"],
                 font=("Segoe UI", 8), padx=10).pack(side=tk.RIGHT)
        tk.Label(right_bar,
                 text="ShieldScan  •  Defensive & educational use only  ",
                 fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 8)).pack(side=tk.RIGHT)

    # ══════════════════════════════════════════════════════════
    # Output helpers
    # ══════════════════════════════════════════════════════════

    def _clear_output(self):
        self._txt.configure(state=tk.NORMAL)
        self._txt.delete("1.0", tk.END)
        self._txt.configure(state=tk.DISABLED)

    def _log(self, text: str, tag: str | None = None):
        self._q.put(("log", text, tag))

    def _log_line(self, line: str):
        self._q.put(("logline", line, None))

    def _poll_queue(self):
        try:
            while True:
                kind, data, tag = self._q.get_nowait()
                if kind == "log":
                    self._do_append(data, tag)
                elif kind == "logline":
                    self._do_append(data, self._tag_line(data))
                elif kind == "risk":
                    score, verdict = data, tag
                    self._score, self._verdict = score, verdict
                    clr = _VERDICT_COLOR.get(verdict, C["muted"])
                    self._lbl_score_big.configure(
                        text=str(score), fg=clr)
                    self._lbl_verdict.configure(
                        text=f"● {verdict}", fg=clr)
                    self._lbl_verdict_desc.configure(
                        text=_VERDICT_DESC.get(verdict, ""), fg=clr)
                    self.after(30, self._draw_meter,    score, clr)
                    self.after(30, self._draw_progress, score, clr)
                elif kind == "counts":
                    h, m, l, t = data
                    self._count_rows["HIGH"].configure(text=str(h))
                    self._count_rows["MED"].configure(text=str(m))
                    self._count_rows["LOW"].configure(text=str(l))
                    self._count_rows["TOTAL"].configure(text=str(t))
                    self._pills["HIGH"].configure(text=f"  HIGH  {h}  ")
                    self._pills["MED"].configure(text=f"  MED  {m}  ")
                    self._pills["LOW"].configure(text=f"  LOW  {l}  ")
                    self._lbl_scan_msg.configure(
                        text=f"{t} finding{'s' if t!=1 else ''} detected  ")
                elif kind == "done":
                    self._on_scan_done(*data)
        except queue.Empty:
            pass
        self.after(40, self._poll_queue)

    def _do_append(self, text: str, tag: str | None):
        self._txt.configure(state=tk.NORMAL)
        if tag:
            self._txt.insert(tk.END, text, tag)
        else:
            self._txt.insert(tk.END, text)
        self._txt.configure(state=tk.DISABLED)
        self._txt.see(tk.END)

    def _tag_line(self, line: str) -> str:
        ll = line.lower()
        if "[hig]" in ll or "[!!]" in ll or "severity: high" in ll:
            return "high"
        if "[med]" in ll or "severity: medium" in ll:
            return "med"
        if "[low]" in ll:
            return "low"
        if "[ok]" in ll or "no finding" in ll:
            return "ok"
        if "ml:" in ll or "att&ck:" in ll or "action:" in ll or "conf=" in ll:
            return "ml"
        if "warning" in ll or "stale" in ll or "⚠" in line:
            return "warn"
        if line.strip().startswith(("+==", "|", "+-", "  +")):
            return "banner"
        if line.strip().startswith(("Log ", "Report", "Started")):
            return "dim"
        return ""

    # ══════════════════════════════════════════════════════════
    # Scan execution
    # ══════════════════════════════════════════════════════════

    def _build_cmd(self) -> list[str]:
        cmd  = [sys.executable, _MAIN_PY]
        core = [mid for mid, *_ in _MODULES if mid != "Baseline Diff"]
        all_core = all(self._mods[k].get() for k in core)
        if all_core and not self._mods["Baseline Diff"].get():
            cmd.append("--all")
        elif all_core:
            cmd += ["--all", "--diff"]
        else:
            for mid, var in self._mods.items():
                if var.get():
                    cmd.append(_CLI_FLAGS[mid])
        if self._no_ml.get():     cmd.append("--no-ml")
        if self._no_report.get(): cmd.append("--no-report")
        w = self._watch.get().strip()
        if w.isdigit() and int(w) > 0:
            cmd += ["--watch", w]
        return cmd

    def _run_scan(self):
        if self._scanning:
            return
        if not any(v.get() for v in self._mods.values()):
            messagebox.showwarning(
                "Nothing Selected",
                "Please enable at least one scan module in the left panel.")
            return

        self._scanning   = True
        self._scan_start = datetime.now()
        self._run_btn.configure(state=tk.DISABLED)
        self._stop_btn.configure(state=tk.NORMAL)
        self._status_dot.configure(fg=C["green"])
        self._sv_status.set("Scan in progress…")
        self._sv_elapsed.set("")

        # Switch centre panel to output view
        self._show_output()

        # Show scan-info bar (above the text frame, safely using before=)
        self._scan_info.pack(fill=tk.X, before=self._output_tf)

        # Reset state
        self._score = 0;  self._verdict = ""
        self._lbl_score_big.configure(text="—", fg=C["faint"])
        self._lbl_verdict.configure(text="Scanning…", fg=C["muted"])
        self._lbl_verdict_desc.configure(text="", fg=C["muted"])
        for k in ("HIGH", "MED", "LOW", "TOTAL"):
            self._count_rows[k].configure(text="0")
        for k, v in self._pills.items():
            v.configure(text=f"  {k}  0  ")
        self._lbl_scan_msg.configure(text="Scanning…")
        self._info_rows["Status"].configure(text="Scanning", fg=C["green"])
        self._info_rows["Elapsed"].configure(text="…")
        self.after(30, self._draw_meter,    0, C["faint"])
        self.after(30, self._draw_progress, 0, C["faint"])
        self._clear_output()

        cmd = self._build_cmd()
        self._log(f"  {'─'*64}\n", "dim")
        self._log(f"  {' '.join(cmd)}\n", "dim")
        self._log(f"  {'─'*64}\n\n", "dim")

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                cwd=_HERE,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as exc:
            self._log(f"\n  ERROR: Could not start scanner:\n  {exc}\n\n",
                      "high")
            self._reset_scan_ui()
            return

        threading.Thread(target=self._stream, daemon=True).start()
        self._tick_elapsed()

    def _tick_elapsed(self):
        if not self._scanning or not self._scan_start:
            return
        secs = int((datetime.now() - self._scan_start).total_seconds())
        t = f"{secs // 60:02d}:{secs % 60:02d}"
        self._sv_elapsed.set(f"   {t}")
        self._info_rows["Elapsed"].configure(text=t)
        self.after(1000, self._tick_elapsed)

    def _stop_scan(self):
        if self._proc:
            try: self._proc.terminate()
            except Exception: pass
        self._q.put(("log", "\n  Scan stopped by user.\n", "warn"))
        self._q.put(("done", (-1, 0, 0, 0), None))

    def _stream(self):
        high = med = low = total = 0
        for raw in self._proc.stdout:
            line = _strip(raw)
            m = _RISK_RE.search(line)
            if m:
                score   = int(m.group(1))
                mv      = _VERD_RE.search(line[m.start():])
                verdict = mv.group(1).upper() if mv else "—"
                self._q.put(("risk", score, verdict))
            ll = line.lower()
            changed = False
            if "[hig]" in ll or "[!!]" in ll:
                high += 1;  total += 1;  changed = True
            elif "[med]" in ll:
                med  += 1;  total += 1;  changed = True
            elif "[low]" in ll:
                low  += 1;  total += 1;  changed = True
            if changed:
                self._q.put(("counts", (high, med, low, total), None))
            self._log_line(line)
        self._proc.wait()
        self._q.put(("done",
                     (self._proc.returncode, high, med, low), None))

    def _on_scan_done(self, rc: int, high: int, med: int, low: int):
        self._scanning = False
        self._proc     = None
        elapsed = ""
        if self._scan_start:
            secs    = int((datetime.now() - self._scan_start).total_seconds())
            elapsed = f"{secs // 60:02d}:{secs % 60:02d}"
            self._sv_elapsed.set(f"   {elapsed}")
            self._info_rows["Elapsed"].configure(text=elapsed)

        self._reset_scan_ui()
        ts = datetime.now().strftime("%H:%M:%S")

        if rc == 0:
            self._sv_status.set(
                f"Scan complete ({elapsed})  —  No threats found.")
            self._info_rows["Status"].configure(
                text="Clean ✓", fg=C["green"])
            self._lbl_scan_msg.configure(text="Scan complete — no findings.")
        elif rc == 1:
            self._sv_status.set(
                f"Scan complete ({elapsed})  —  "
                f"{high} HIGH  {med} MED  {low} LOW")
            self._info_rows["Status"].configure(
                text="Done", fg=C["muted"])
        else:
            self._sv_status.set(f"Scan stopped — {ts}")
            self._info_rows["Status"].configure(
                text="Stopped", fg=C["faint"])
            self._lbl_scan_msg.configure(text="Scan stopped.")

        rpt = self._find_report()
        self._last_report = rpt
        self._info_rows["Report"].configure(
            text="Ready" if rpt else "None",
            fg=C["blue"] if rpt else C["faint"])

        # Tag the report with the current user
        if rpt:
            try:
                _tag_report(rpt, self._current_user, self._score, self._verdict)
            except Exception:
                pass

        # Show review dialog for non-clean scans
        if self._verdict and self._verdict != "CLEAN":
            self.after(600, self._show_review_dialog)

        # Keep history list up-to-date only when the History tab is visible
        if self._active_tab == "history":
            try:
                self._refresh_history()
            except Exception:
                pass

        # Auto-email logic
        if rpt and self._current_email:
            ecfg = self._load_email_cfg()
            smtp_ready = (ecfg.get("smtp_server") and
                          ecfg.get("username") and
                          ecfg.get("password"))
            if smtp_ready:
                if self._is_scheduled_scan and self._sched_cfg.get("auto_email", True):
                    # Scheduled scan — send silently without prompting
                    self.after(800, lambda r=rpt: self._silent_send_report(r))
                else:
                    # Manual scan — ask first
                    self.after(500, lambda r=rpt: self._auto_send_report(r))

        self._is_scheduled_scan = False   # reset flag for next manual scan

    def _show_review_dialog(self):
        """Show a finding review dialog with fix instructions after a non-clean scan."""
        # Collect HIGH findings from the output text
        findings: list[str] = []
        try:
            content = self._txt.get("1.0", tk.END)
            for line in content.splitlines():
                stripped = line.strip()
                if stripped and ("[HIG]" in stripped or "[!!]" in stripped
                                 or "[HIGH]" in stripped.upper()):
                    clean = re.sub(r"\[.*?\]\s*", "", stripped).strip()
                    if clean and len(clean) > 10:
                        findings.append(clean[:160])
        except Exception:
            pass

        if not findings:
            findings = [f"Verdict: {self._verdict}  —  Risk Score: {self._score}/100"]

        dlg = tk.Toplevel(self)
        dlg.title("Review Findings & Fix Instructions")
        dlg.configure(bg=C["surface"])
        dlg.resizable(True, True)
        dlg.grab_set()
        dlg.transient(self)
        dlg.geometry("780x560")

        # ── Header ────────────────────────────────────────────
        hdr = tk.Frame(dlg, bg=C["card"])
        hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg=C["border"], height=1).pack(side=tk.BOTTOM, fill=tk.X)
        vclr = _VERDICT_COLOR.get(self._verdict, C["yellow"])
        tk.Label(hdr, text=f"⚠  {self._verdict}  —  Risk Score: {self._score}/100",
                 fg=vclr, bg=C["card"],
                 font=("Segoe UI", 11, "bold"),
                 padx=20, pady=12).pack(side=tk.LEFT)
        tk.Label(hdr, text="Review each finding and select what you know about it.",
                 fg=C["muted"], bg=C["card"],
                 font=("Segoe UI", 8), padx=20).pack(side=tk.LEFT)

        # ── Scrollable findings list ──────────────────────────
        canvas = tk.Canvas(dlg, bg=C["bg"], highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(dlg, style="Slim.Vertical.TScrollbar",
                            orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        inner = tk.Frame(canvas, bg=C["bg"])
        _wid  = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(_wid, width=e.width))
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        def _mw(e): canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        canvas.bind("<Enter>", lambda _: canvas.bind_all("<MouseWheel>", _mw))
        canvas.bind("<Leave>", lambda _: canvas.unbind_all("<MouseWheel>"))

        # Load remediation knowledge for findings
        try:
            from ml_model.remediation import get_remediation
        except Exception:
            get_remediation = None

        for idx, finding_text in enumerate(findings[:20]):
            self._review_finding_card(inner, idx, finding_text, get_remediation)

        # ── Bottom close button ───────────────────────────────
        foot = tk.Frame(dlg, bg=C["surface"])
        foot.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=12)
        tk.Button(foot, text="  Close  ", command=dlg.destroy,
                  bg=C["green"], fg=C["bg"],
                  activebackground="#4ac760",
                  font=("Segoe UI", 9, "bold"),
                  relief=tk.FLAT, bd=0,
                  padx=14, pady=7, cursor="hand2").pack(side=tk.RIGHT)

    def _review_finding_card(self, parent, idx: int,
                              finding_text: str, get_remediation):
        """One card per finding in the review dialog."""
        card = tk.Frame(parent, bg=C["surface"])
        card.pack(fill=tk.X, padx=16, pady=6)
        tk.Frame(card, bg=C["border"], height=1).pack(fill=tk.X, side=tk.BOTTOM)

        # ── Finding text ──────────────────────────────────────
        top = tk.Frame(card, bg=C["surface"])
        top.pack(fill=tk.X, padx=14, pady=(10, 4))
        tk.Label(top, text=f"Finding {idx+1}", fg=C["red"], bg=C["surface"],
                 font=("Segoe UI", 7, "bold")).pack(side=tk.LEFT)
        tk.Label(card, text=finding_text,
                 fg=C["text"], bg=C["surface"],
                 font=("Segoe UI", 9), wraplength=700,
                 justify=tk.LEFT, anchor="w",
                 padx=14, pady=4).pack(fill=tk.X)

        # ── Try to find auto remediation ──────────────────────
        steps: list[str] = []
        mitre: list[str] = []
        if get_remediation:
            try:
                # guess category from keywords in finding text
                ftl = finding_text.lower()
                cat = ("ROOTKIT_PROCESS" if "hidden" in ftl and "process" in ftl
                       else "ROOTKIT_DRIVER"  if "driver" in ftl or "unsigned" in ftl
                       else "ROOTKIT_NETWORK" if "port" in ftl or "socket" in ftl
                       else "ROOTKIT_MEMORY"  if "inject" in ftl or "shellcode" in ftl
                       else "PERSISTENCE"     if "persist" in ftl or "startup" in ftl or "task" in ftl
                       else "ROOTKIT_REGISTRY" if "registr" in ftl or "run key" in ftl
                       else "SUSPICIOUS")
                rem   = get_remediation(cat)
                steps = rem.get("steps", [])
                mitre = rem.get("mitre", [])
            except Exception:
                pass

        rem_frame = tk.Frame(card, bg=C["surface"])
        rem_frame.pack(fill=tk.X, padx=14, pady=(2, 8))

        if steps:
            # Show auto-generated fix steps
            tk.Label(rem_frame, text="Recommended Fix Steps:",
                     fg=C["green"], bg=C["surface"],
                     font=("Segoe UI", 8, "bold")).pack(anchor="w")
            for s in steps[:5]:
                tk.Label(rem_frame, text=f"  • {s}",
                         fg=C["muted"], bg=C["surface"],
                         font=("Segoe UI", 8), wraplength=680,
                         justify=tk.LEFT, anchor="w").pack(fill=tk.X)
            if mitre:
                tk.Label(rem_frame,
                         text="MITRE ATT&CK: " + "  ".join(mitre),
                         fg=C["purple"], bg=C["surface"],
                         font=("Segoe UI", 7)).pack(anchor="w", pady=(4, 0))
        else:
            # No known remediation — show dropdown
            tk.Label(rem_frame,
                     text="No automatic fix found for this finding. What do you know about it?",
                     fg=C["yellow"], bg=C["surface"],
                     font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 4))

            ctrl_row = tk.Frame(rem_frame, bg=C["surface"])
            ctrl_row.pack(fill=tk.X)

            sv_choice = tk.StringVar(value="Select…")
            options   = ["Known", "Unknown", "Search"]
            dd = ttk.Combobox(ctrl_row, textvariable=sv_choice,
                              values=options, state="readonly",
                              width=14,
                              font=("Segoe UI", 9))
            dd.pack(side=tk.LEFT, padx=(0, 10))

            info_frame = tk.Frame(ctrl_row, bg=C["surface"])
            info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

            def _on_choice(*_, _iframe=info_frame, _sv=sv_choice,
                           _ft=finding_text):
                for w in _iframe.winfo_children():
                    w.destroy()
                choice = _sv.get()

                if choice == "Known":
                    tk.Label(_iframe,
                             text="Describe what you know (saved to local KB):",
                             fg=C["muted"], bg=C["surface"],
                             font=("Segoe UI", 8)).pack(anchor="w")
                    entry_sv = tk.StringVar()
                    e = tk.Entry(_iframe, textvariable=entry_sv,
                                 bg=C["card"], fg=C["text"],
                                 insertbackground=C["text"],
                                 relief=tk.FLAT, font=("Segoe UI", 9),
                                 highlightthickness=1,
                                 highlightcolor=C["green"],
                                 highlightbackground=C["border"],
                                 width=52)
                    e.pack(fill=tk.X, ipady=4, pady=(2, 4))

                    def _save_known(_sv=entry_sv, _ft=_ft):
                        note = _sv.get().strip()
                        if not note:
                            return
                        try:
                            kb_path = _KB_JSON
                            kb = {}
                            if os.path.exists(kb_path):
                                with open(kb_path, encoding="utf-8") as f:
                                    kb = json.load(f)
                            kb.setdefault("user_notes", []).append({
                                "finding": _ft[:120],
                                "note":    note,
                                "ts":      datetime.now().isoformat(),
                                "user":    self._current_user,
                            })
                            with open(kb_path, "w", encoding="utf-8") as f:
                                json.dump(kb, f, indent=2)
                            tk.Label(_iframe, text="✓ Saved to knowledge base.",
                                     fg=C["green"], bg=C["surface"],
                                     font=("Segoe UI", 8)).pack(anchor="w")
                        except Exception as exc:
                            tk.Label(_iframe, text=f"Save failed: {exc}",
                                     fg=C["red"], bg=C["surface"],
                                     font=("Segoe UI", 8)).pack(anchor="w")

                    tk.Button(_iframe, text="Save Note",
                              command=_save_known,
                              bg=C["green"], fg=C["bg"],
                              font=("Segoe UI", 8, "bold"),
                              relief=tk.FLAT, bd=0,
                              padx=10, pady=3,
                              cursor="hand2").pack(anchor="w")

                elif choice == "Unknown":
                    tk.Label(_iframe,
                             text="Marked as unknown — consider isolating this machine.",
                             fg=C["muted"], bg=C["surface"],
                             font=("Segoe UI", 8),
                             wraplength=480).pack(anchor="w")

                elif choice == "Search":
                    # Search local knowledge base first, then open browser
                    found_local = []
                    try:
                        import difflib
                        if os.path.exists(_KB_JSON):
                            with open(_KB_JSON, encoding="utf-8") as f:
                                kb = json.load(f)
                            # search benign entries
                            for section in kb.values():
                                entries = section if isinstance(section, list) else []
                                for entry in entries:
                                    if isinstance(entry, str):
                                        ratio = difflib.SequenceMatcher(
                                            None, _ft.lower(),
                                            entry.lower()).ratio()
                                        if ratio > 0.45:
                                            found_local.append(entry)
                                    elif isinstance(entry, dict):
                                        note = entry.get("finding", entry.get("note", ""))
                                        ratio = difflib.SequenceMatcher(
                                            None, _ft.lower(),
                                            note.lower()).ratio()
                                        if ratio > 0.45:
                                            found_local.append(
                                                note + " — " + entry.get("note", ""))
                    except Exception:
                        pass

                    if found_local:
                        tk.Label(_iframe,
                                 text=f"Found {len(found_local)} local KB match(es):",
                                 fg=C["green"], bg=C["surface"],
                                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
                        for m in found_local[:3]:
                            tk.Label(_iframe, text=f"  • {m[:120]}",
                                     fg=C["muted"], bg=C["surface"],
                                     font=("Segoe UI", 8),
                                     wraplength=460).pack(anchor="w")
                    else:
                        tk.Label(_iframe,
                                 text="No local KB match found — opening browser search…",
                                 fg=C["muted"], bg=C["surface"],
                                 font=("Segoe UI", 8)).pack(anchor="w")

                    # Always open a web search
                    query = _ft[:120].replace(" ", "+")
                    url   = f"https://www.google.com/search?q=windows+security+{query}"
                    webbrowser.open(url)

            sv_choice.trace_add("write", _on_choice)

    def _auto_send_report(self, rpt: str):
        """Ask user whether to email the report (used after manual scans)."""
        ans = messagebox.askyesno(
            "Send Report by Email?",
            f"Scan complete.\n\nSend report to your registered email?\n{self._current_email}",
        )
        if ans:
            self._send_report_email(report_path=rpt, auto_recipient=self._current_email)

    def _silent_send_report(self, rpt: str):
        """Send report email silently in background (used after scheduled scans)."""
        ecfg = self._load_email_cfg()
        if not ecfg.get("smtp_server"):
            return
        recipient = self._current_email or ecfg.get("recipient", "")
        if not recipient:
            return
        sender = ecfg.get("username", "")

        def _send():
            try:
                with open(rpt, encoding="utf-8", errors="replace") as fh:
                    html_body = fh.read()

                plain_body = (
                    f"ShieldScan {self.VERSION} — Scheduled Scan Report\n"
                    f"{'─'*50}\n\n"
                    f"Date       : {datetime.now().strftime('%d %b %Y  %H:%M')}\n"
                    f"User       : {self._current_user}\n"
                    f"Risk Score : {self._score}/100\n"
                    f"Verdict    : {self._verdict or 'See full report'}\n\n"
                    f"This was an automatically scheduled scan.\n"
                    f"Generated by ShieldScan {self.VERSION}"
                )

                msg = MIMEMultipart("alternative")
                msg["From"]    = sender
                msg["To"]      = recipient
                msg["Subject"] = (
                    f"[ShieldScan] Scheduled Report  "
                    f"{datetime.now().strftime('%d %b %Y %H:%M')}"
                )
                msg.attach(MIMEText(plain_body, "plain", "utf-8"))
                msg.attach(MIMEText(html_body,  "html",  "utf-8"))

                ctx  = ssl.create_default_context()
                port = int(ecfg.get("smtp_port", 587))
                if ecfg.get("use_tls", True):
                    with smtplib.SMTP(ecfg["smtp_server"], port) as s:
                        s.ehlo(); s.starttls(context=ctx)
                        s.login(sender, ecfg["password"])
                        s.sendmail(sender, recipient, msg.as_string())
                else:
                    with smtplib.SMTP_SSL(ecfg["smtp_server"], port, context=ctx) as s:
                        s.login(sender, ecfg["password"])
                        s.sendmail(sender, recipient, msg.as_string())

                self.after(0, self._sv_status.set,
                           f"Scheduled report emailed to {recipient}")
            except Exception as exc:
                self.after(0, self._sv_status.set,
                           f"Auto-email failed: {exc}")

        threading.Thread(target=_send, daemon=True).start()

    def _reset_scan_ui(self):
        self._run_btn.configure(state=tk.NORMAL)
        self._stop_btn.configure(state=tk.DISABLED)
        self._status_dot.configure(fg=C["faint"])

    def _find_report(self) -> str | None:
        rpts = glob.glob(os.path.join(_LOGS, "report_*.html"))
        return max(rpts, key=os.path.getmtime) if rpts else None

    # ══════════════════════════════════════════════════════════
    # Tool helpers
    # ══════════════════════════════════════════════════════════

    def _tool_run(self, cmd: list[str], label: str):
        if self._scanning:
            messagebox.showwarning(
                "Busy", "Please wait for the current scan to finish.")
            return
        self._show_output()
        self._sv_status.set(label)
        self._log(f"\n  ── {label} ──\n\n", "banner")

        def _t():
            p = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", cwd=_HERE,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for raw in p.stdout:
                self._log_line(_strip(raw))
            p.wait()
            self._q.put(("log", "\n  Done.\n", "ok"))
            self.after(0, self._sv_status.set, "Ready")

        threading.Thread(target=_t, daemon=True).start()

    def _open_report(self):
        r = self._last_report or self._find_report()
        if r and os.path.exists(r):
            webbrowser.open("file:///" + r.replace("\\", "/"))
        else:
            messagebox.showinfo("No Report",
                                "No HTML report found yet.\n\n"
                                "Run a scan first, then click Open Last Report.")

    def _open_logs(self):
        os.makedirs(_LOGS, exist_ok=True)
        os.startfile(_LOGS)

    def _capture_baseline(self):
        baseline_dir = os.path.join(_LOGS, "baselines")
        os.makedirs(baseline_dir, exist_ok=True)
        self._tool_run([sys.executable, _MAIN_PY, "--baseline"],
                       "Capturing system baseline snapshot…")
        # After the tool finishes, notify user where baselines are saved
        def _notify():
            files = sorted(
                glob.glob(os.path.join(baseline_dir, "baseline_*.json")),
                key=os.path.getmtime, reverse=True)
            if files:
                latest = os.path.basename(files[0])
                self._sv_status.set(
                    f"Baseline saved → logs/baselines/{latest}")
                messagebox.showinfo(
                    "Baseline Captured",
                    f"Snapshot saved successfully!\n\n"
                    f"File:  {latest}\n"
                    f"Location:  {baseline_dir}\n\n"
                    "Use 'Compare to Baseline' in the next scan\n"
                    "to see what changed.",
                )
            else:
                messagebox.showinfo(
                    "Baseline Captured",
                    f"Snapshot saved to:\n{baseline_dir}")
        self.after(3000, _notify)

    def _list_baselines(self):
        baseline_dir = os.path.join(_LOGS, "baselines")
        files = sorted(
            glob.glob(os.path.join(baseline_dir, "baseline_*.json")),
            key=os.path.getmtime, reverse=True)

        if not files:
            messagebox.showinfo(
                "No Baselines",
                "No baseline snapshots found.\n\n"
                "Click 'Capture Baseline' first to save a snapshot\n"
                "of your current system state."
            )
            return

        dlg = tk.Toplevel(self)
        dlg.title("Saved Baselines")
        dlg.configure(bg=C["surface"])
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.transient(self)
        dlg.geometry("500x340")

        hdr = tk.Frame(dlg, bg=C["card"])
        hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg=C["border"], height=1).pack(side=tk.BOTTOM, fill=tk.X)
        tk.Label(hdr, text=f"Saved Baselines  ({len(files)} found)",
                 fg=C["white"], bg=C["card"],
                 font=("Segoe UI", 10, "bold"),
                 padx=20, pady=12).pack(side=tk.LEFT)

        body = tk.Frame(dlg, bg=C["surface"])
        body.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)

        for f in files[:10]:
            fname = os.path.basename(f)
            try:
                ts = fname.replace("baseline_", "").replace(".json", "")
                dt = datetime.strptime(ts, "%Y%m%d_%H%M%S")
                label = dt.strftime("%d %b %Y  %H:%M:%S")
            except Exception:
                label = fname

            row = tk.Frame(body, bg=C["card"])
            row.pack(fill=tk.X, pady=3)
            tk.Label(row, text=f"  📸  {label}",
                     fg=C["text"], bg=C["card"],
                     font=("Segoe UI", 9), pady=8).pack(side=tk.LEFT)
            tk.Label(row, text=fname,
                     fg=C["faint"], bg=C["card"],
                     font=("Segoe UI", 7), padx=12).pack(side=tk.RIGHT)

        foot = tk.Frame(dlg, bg=C["surface"])
        foot.pack(fill=tk.X, padx=20, pady=(0, 16))
        tk.Button(foot, text="Open Baselines Folder",
                  command=lambda: os.startfile(baseline_dir),
                  bg=C["card"], fg=C["blue"],
                  activebackground=C["card2"],
                  activeforeground=C["white"],
                  font=("Segoe UI", 9),
                  relief=tk.FLAT, bd=0,
                  padx=12, pady=6, cursor="hand2").pack(side=tk.LEFT)
        tk.Button(foot, text="Close", command=dlg.destroy,
                  bg=C["surface"], fg=C["muted"],
                  activebackground=C["card"],
                  font=("Segoe UI", 9),
                  relief=tk.FLAT, bd=0,
                  padx=12, pady=6, cursor="hand2").pack(side=tk.RIGHT)

    def _reset_fim(self):
        if messagebox.askyesno(
            "Reset File Integrity Baseline",
            "This will delete the saved file hash baseline.\n\n"
            "The next scan will create a new baseline and won't\n"
            "report any file changes until the scan after that.\n\n"
            "Continue?",
        ):
            self._tool_run([sys.executable, _MAIN_PY, "--reset-fim"],
                           "Resetting file integrity baseline…")

    def _update_ml(self, kaggle: bool):
        cmd = [sys.executable, _MAIN_PY, "--update-ml"]
        if kaggle: cmd.append("--kaggle")
        self._tool_run(
            cmd,
            "Training AI classifier with Kaggle data…"
            if kaggle else "Training AI threat classifier…",
        )

    def _analyze_dump(self):
        """Let the user pick a memory dump file and run Volatility on it."""
        path = filedialog.askopenfilename(
            title="Select Memory Dump File",
            filetypes=[
                ("Memory dump files", "*.raw *.dmp *.mem *.vmem *.img *.bin"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return

        self._show_output()
        self._sv_status.set(f"Analyzing dump: {os.path.basename(path)}")
        self._log(f"\n  ── Memory Dump Analysis ──\n  File: {path}\n\n", "banner")

        vol_py = os.path.join(_HERE, "volatility3", "vol.py")
        if not os.path.exists(vol_py):
            vol_py = os.path.join(_HERE, "volatility_analyzer.py")

        def _run_plugin(plugin: str) -> list[str]:
            return [sys.executable, vol_py, "-f", path, plugin]

        def _t():
            plugins = ["windows.pslist", "windows.pstree", "windows.malfind",
                       "windows.netstat", "windows.dlllist"]
            for plugin in plugins:
                self._q.put(("log", f"\n  ┌─ {plugin} ─\n", "banner"))
                p = subprocess.Popen(
                    _run_plugin(plugin),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace",
                    cwd=_HERE,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                for raw in p.stdout:
                    self._log_line(_strip(raw))
                p.wait()
                if p.returncode not in (0, 1):
                    self._q.put(("log",
                                 f"  ⚠  Plugin returned code {p.returncode}\n", "warn"))

            self._q.put(("log", "\n  Memory dump analysis complete.\n", "ok"))
            self.after(0, self._sv_status.set, "Ready")

        threading.Thread(target=_t, daemon=True).start()

    def _save_report_image(self):
        """Generate a shareable summary PNG for the last scan report."""
        r = self._last_report or self._find_report()
        if not r or not os.path.exists(r):
            messagebox.showinfo("No Report",
                                "No scan report found.\nRun a scan first.")
            return

        if not _PIL_OK:
            messagebox.showwarning(
                "Pillow Not Installed",
                "Generating report images requires Pillow.\n\n"
                "Install it with:\n    pip install Pillow\n\n"
                "Then try again.",
            )
            return

        # Derive output path
        out_path = r.replace(".html", "_summary.png")

        # Parse some values from the report filename
        fname = os.path.basename(r)
        try:
            ts_part = fname.replace("report_", "").replace(".html", "")
            dt_obj  = datetime.strptime(ts_part, "%Y%m%d_%H%M%S")
            date_str = dt_obj.strftime("%d %b %Y  %H:%M")
        except Exception:
            date_str = datetime.now().strftime("%d %b %Y  %H:%M")

        score   = self._score
        verdict = self._verdict or "—"
        vclr_hex = {
            "CLEAN":       "#3fb950",
            "LOW RISK":    "#58a6ff",
            "SUSPICIOUS":  "#d29922",
            "COMPROMISED": "#f85149",
        }.get(verdict, "#484f58")

        # Count values
        def _int_label(key):
            lbl = self._count_rows.get(key)
            return lbl.cget("text") if lbl else "0"

        h_cnt = _int_label("HIGH")
        m_cnt = _int_label("MED")
        l_cnt = _int_label("LOW")
        t_cnt = _int_label("TOTAL")

        W, H = 900, 480

        def _hex(h):
            h = h.lstrip("#")
            return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

        img = Image.new("RGB", (W, H), _hex("#0d1117"))
        d   = ImageDraw.Draw(img)

        def _rect(x0, y0, x1, y1, fill, radius=8):
            d.rounded_rectangle([x0, y0, x1, y1], radius=radius, fill=_hex(fill))

        def _txt(x, y, text, fill="#c9d1d9", size=14, bold=False):
            try:
                if bold:
                    fnt = ImageFont.truetype("C:/Windows/Fonts/segoeuib.ttf", size)
                else:
                    fnt = ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", size)
            except Exception:
                fnt = ImageFont.load_default()
            d.text((x, y), text, font=fnt, fill=_hex(fill))

        # Background card
        _rect(20, 20, W-20, H-20, "#161b22", radius=12)

        # Top accent bar
        _rect(20, 20, W-20, 64, "#21262d", radius=12)
        _rect(20, 20, W-20, 64, "#21262d", radius=0)   # flatten bottom corners

        # Shield icon + brand
        _txt(40, 28, "🛡 ShieldScan", fill="#f0f6fc", size=18, bold=True)
        _txt(W-260, 36, f"Scan Report  •  {date_str}", fill="#8b949e", size=11)

        # Divider
        d.line([(40, 76), (W-40, 76)], fill=_hex("#30363d"), width=1)

        # Risk score — large
        _txt(50, 100, "RISK SCORE", fill="#484f58", size=9)
        _txt(50, 118, str(score), fill=vclr_hex, size=72, bold=True)
        _txt(50, 200, "/ 100", fill="#8b949e", size=16)

        # Verdict badge
        _rect(200, 120, 390, 168, vclr_hex, radius=8)
        _txt(215, 133, verdict, fill="#0d1117", size=20, bold=True)

        # User info
        _txt(200, 186, f"User: {self._current_user}", fill="#8b949e", size=11)

        # Finding counts
        for i, (lbl, cnt, clr) in enumerate((
            ("HIGH",  h_cnt, "#f85149"),
            ("MED",   m_cnt, "#d29922"),
            ("LOW",   l_cnt, "#58a6ff"),
            ("TOTAL", t_cnt, "#8b949e"),
        )):
            bx = 460 + i * 110
            _rect(bx, 100, bx+96, 190, "#21262d", radius=8)
            _txt(bx+10, 112, lbl, fill="#484f58", size=9)
            _txt(bx+10, 132, cnt, fill=clr, size=36, bold=True)

        # Module status list
        y_off = 230
        _txt(50, y_off, "MODULES RUN", fill="#484f58", size=9)
        y_off += 18
        mods_on  = [name for mid, name, *_ in _MODULES if self._mods[mid].get()]
        per_line = 3
        for i, name in enumerate(mods_on):
            cx = 50 + (i % per_line) * 270
            cy = y_off + (i // per_line) * 22
            _txt(cx, cy, f"✓ {name}", fill="#3fb950", size=10)

        # Footer
        _rect(20, H-52, W-20, H-20, "#161b22", radius=0)
        _rect(20, H-52, W-20, H-20, "#161b22", radius=12)
        d.line([(40, H-54), (W-40, H-54)], fill=_hex("#30363d"), width=1)
        _txt(40,  H-44, "Generated by ShieldScan — For defensive & educational use only",
             fill="#484f58", size=9)
        _txt(W-280, H-44, f"ShieldScan {self.VERSION}", fill="#484f58", size=9)

        img.save(out_path, "PNG")

        if messagebox.askyesno(
            "Image Saved",
            f"Summary image saved to:\n{out_path}\n\nOpen it now?"
        ):
            os.startfile(out_path)

    # ══════════════════════════════════════════════════════════
    # Scheduled scan
    # ══════════════════════════════════════════════════════════

    def _load_user_schedule(self):
        """Load saved schedule config for the current user and arm it."""
        data = _load_schedules()
        cfg  = data.get(self._current_user, {})
        self._sched_cfg = cfg
        if cfg.get("enabled") and cfg.get("next_run"):
            try:
                self._sched_next = datetime.fromisoformat(cfg["next_run"])
                self._sv_sched_status.set(self._sched_label(cfg))
                self._sv_sched_next.set(
                    self._sched_next.strftime("%d %b  %H:%M"))
            except Exception:
                self._sched_next = None

    def _save_user_schedule(self):
        """Persist current schedule for this user."""
        data = _load_schedules()
        data[self._current_user] = self._sched_cfg
        _save_schedules(data)

    @staticmethod
    def _sched_label(cfg: dict) -> str:
        mode = cfg.get("mode", "daily")
        if mode == "daily":
            return f"Daily  {cfg.get('time','—')}"
        if mode == "weekly":
            day_names = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
            days = cfg.get("days", [])
            abbr = ",".join(day_names[d] for d in days[:3])
            return f"Weekly  {abbr}  {cfg.get('time','—')}"
        if mode == "interval":
            h = cfg.get("interval_hours", 6)
            return f"Every {h}h"
        return "Once"

    def _schedule_tick(self):
        """Called every 30 s — fires a scan when it's time."""
        try:
            cfg = self._sched_cfg
            if cfg.get("enabled") and self._sched_next:
                now = datetime.now()
                if now >= self._sched_next and not self._scanning:
                    self._run_scheduled_scan()
        except Exception:
            pass
        # Refresh the countdown label every tick
        if self._sched_next and self._sched_cfg.get("enabled"):
            remaining = self._sched_next - datetime.now()
            secs = int(remaining.total_seconds())
            if secs > 0:
                if secs < 3600:
                    countdown = f"in {secs//60}m {secs%60:02d}s"
                elif secs < 86400:
                    countdown = f"in {secs//3600}h {(secs%3600)//60}m"
                else:
                    countdown = self._sched_next.strftime("%d %b  %H:%M")
                self._sv_sched_next.set(countdown)
        self.after(30_000, self._schedule_tick)

    def _run_scheduled_scan(self):
        """Trigger a scan on behalf of the scheduler."""
        self._is_scheduled_scan = True

        # Restore module selection from saved schedule
        saved_mods = self._sched_cfg.get("modules", [])
        if saved_mods:
            for mid in self._mods:
                self._mods[mid].set(mid in saved_mods)

        # Compute and persist the next run time before starting
        mode       = self._sched_cfg.get("mode", "daily")
        time_str   = self._sched_cfg.get("time", "09:00")
        days       = self._sched_cfg.get("days", list(range(7)))
        interval_h = self._sched_cfg.get("interval_hours", 6)

        # For "once" mode, disable after firing
        if mode == "once":
            self._sched_cfg["enabled"] = False
            self._sched_next = None
            self._sv_sched_status.set("Off")
            self._sv_sched_next.set("—")
        else:
            nxt = _next_run_for(mode, time_str, days, interval_h)
            self._sched_next = nxt
            self._sched_cfg["next_run"] = nxt.isoformat()
            self._sv_sched_next.set(nxt.strftime("%d %b  %H:%M"))

        self._save_user_schedule()
        self._run_scan()

    # ── Schedule dialog ────────────────────────────────────────

    def _schedule_dialog(self):
        dlg = tk.Toplevel(self)
        dlg.title("Schedule Scan")
        dlg.configure(bg=C["surface"])
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.transient(self)

        cfg = dict(self._sched_cfg)

        # ── Header ─────────────────────────────────────────────
        hdr = tk.Frame(dlg, bg=C["card"])
        hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg=C["border"], height=1).pack(side=tk.BOTTOM, fill=tk.X)
        tk.Label(hdr, text="🕐  Schedule Scan",
                 fg=C["white"], bg=C["card"],
                 font=("Segoe UI", 11, "bold"),
                 padx=20, pady=12).pack(side=tk.LEFT)

        wrap = tk.Frame(dlg, bg=C["surface"])
        wrap.pack(fill=tk.BOTH, padx=28, pady=20)

        def _sep(): tk.Frame(wrap, bg=C["border"], height=1).pack(fill=tk.X, pady=10)
        def _lbl(text, fg="muted"):
            tk.Label(wrap, text=text, fg=C[fg], bg=C["surface"],
                     font=("Segoe UI", 7, "bold"), anchor="w").pack(fill=tk.X)

        # ── Enable toggle ──────────────────────────────────────
        sv_enabled = tk.BooleanVar(value=bool(cfg.get("enabled", False)))
        en_row = tk.Frame(wrap, bg=C["surface"])
        en_row.pack(fill=tk.X, pady=(0, 4))
        en_box = tk.Label(en_row, text="  ", width=2, bg=C["card"],
                          font=("Consolas", 8))
        en_box.pack(side=tk.LEFT)
        en_lbl = tk.Label(en_row, text="Enable scheduled scanning",
                          fg=C["muted"], bg=C["surface"],
                          font=("Segoe UI", 9))
        en_lbl.pack(side=tk.LEFT, padx=(8, 0))

        def _ref_en(*_):
            if sv_enabled.get():
                en_box.configure(bg=C["green"], text="✓", fg=C["bg"])
                en_lbl.configure(fg=C["text"])
            else:
                en_box.configure(bg=C["card"], text="  ", fg=C["card"])
                en_lbl.configure(fg=C["muted"])
        sv_enabled.trace_add("write", _ref_en); _ref_en()
        for w in (en_row, en_box, en_lbl):
            w.bind("<Button-1>", lambda _: sv_enabled.set(not sv_enabled.get()))

        _sep()
        _lbl("FREQUENCY")

        # Mode radio
        sv_mode = tk.StringVar(value=cfg.get("mode", "daily"))
        modes = [
            ("daily",    "Daily — at a specific time each day"),
            ("weekly",   "Weekly — on selected days"),
            ("interval", "Interval — every N hours"),
            ("once",     "One-time — run once at a specific time"),
        ]
        mode_frame = tk.Frame(wrap, bg=C["surface"])
        mode_frame.pack(fill=tk.X)
        for val, label in modes:
            row = tk.Frame(mode_frame, bg=C["surface"], cursor="hand2")
            row.pack(fill=tk.X, pady=3)
            dot = tk.Label(row, text="○", fg=C["faint"], bg=C["surface"],
                           font=("Segoe UI", 10))
            dot.pack(side=tk.LEFT)
            lbl_w = tk.Label(row, text=f"  {label}",
                             fg=C["muted"], bg=C["surface"],
                             font=("Segoe UI", 9))
            lbl_w.pack(side=tk.LEFT)

            def _sel(v=val, d=dot, l=lbl_w):
                sv_mode.set(v)
                # Reset all dots
                for child in mode_frame.winfo_children():
                    for w2 in child.winfo_children():
                        try:
                            if w2.cget("font") and "10" in str(w2.cget("font")):
                                w2.configure(text="○", fg=C["faint"])
                        except Exception:
                            pass
                d.configure(text="●", fg=C["green"])
                l.configure(fg=C["text"])
                _update_options()

            for w in (row, dot, lbl_w):
                w.bind("<Button-1>", lambda _, fn=_sel: fn())

        _sep()

        # ── Time picker ────────────────────────────────────────
        _lbl("TIME")
        time_parts = cfg.get("time", "09:00").split(":")
        sv_hour = tk.StringVar(value=time_parts[0] if time_parts else "09")
        sv_min  = tk.StringVar(value=time_parts[1] if len(time_parts) > 1 else "00")

        time_row = tk.Frame(wrap, bg=C["surface"])
        time_row.pack(fill=tk.X, pady=(4, 0))

        def _spin(parent, var, from_, to_, width=4):
            sb = tk.Spinbox(parent, textvariable=var,
                            from_=from_, to=to_, wrap=True,
                            width=width, format="%02.0f",
                            bg=C["card"], fg=C["text"],
                            buttonbackground=C["card2"],
                            insertbackground=C["text"],
                            relief=tk.FLAT, font=("Consolas", 11),
                            highlightthickness=1,
                            highlightcolor=C["green"],
                            highlightbackground=C["border"])
            sb.pack(side=tk.LEFT, ipady=4)
            return sb

        _spin(time_row, sv_hour, 0, 23)
        tk.Label(time_row, text=" : ", fg=C["muted"], bg=C["surface"],
                 font=("Consolas", 13)).pack(side=tk.LEFT)
        _spin(time_row, sv_min, 0, 59)
        tk.Label(time_row, text="  (24-hour format)",
                 fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(8, 0))

        # ── Days-of-week (weekly only) ─────────────────────────
        days_host = tk.Frame(wrap, bg=C["surface"])
        sv_days: dict[int, tk.BooleanVar] = {}
        saved_days = cfg.get("days", list(range(5)))  # Mon–Fri default
        day_names  = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
        days_row   = tk.Frame(days_host, bg=C["surface"])
        days_row.pack(fill=tk.X, pady=(8, 0))
        tk.Label(days_row, text="Days:  ", fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 8)).pack(side=tk.LEFT)
        for i, dn in enumerate(day_names):
            bv = tk.BooleanVar(value=(i in saved_days))
            sv_days[i] = bv
            cb_bg = C["green"] if bv.get() else C["card"]
            cb_fg = C["bg"]    if bv.get() else C["muted"]
            btn_d = tk.Button(days_row, text=dn,
                              bg=cb_bg, fg=cb_fg,
                              activebackground=C["card2"],
                              activeforeground=C["white"],
                              font=("Segoe UI", 8, "bold"),
                              relief=tk.FLAT, bd=0,
                              padx=6, pady=3, cursor="hand2")
            btn_d.pack(side=tk.LEFT, padx=2)

            def _toggle_day(b=btn_d, v=bv):
                v.set(not v.get())
                b.configure(bg=C["green"] if v.get() else C["card"],
                            fg=C["bg"]    if v.get() else C["muted"])
            btn_d.configure(command=_toggle_day)

        # ── Interval picker ────────────────────────────────────
        interval_host = tk.Frame(wrap, bg=C["surface"])
        sv_interval   = tk.StringVar(value=str(cfg.get("interval_hours", 6)))
        int_row = tk.Frame(interval_host, bg=C["surface"])
        int_row.pack(fill=tk.X, pady=(8, 0))
        tk.Label(int_row, text="Every  ", fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 9)).pack(side=tk.LEFT)
        _spin(int_row, sv_interval, 1, 72, width=4)
        tk.Label(int_row, text="  hours",
                 fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(4, 0))

        def _update_options():
            mode = sv_mode.get()
            days_host.pack_forget()
            interval_host.pack_forget()
            if mode == "weekly":
                days_host.pack(fill=tk.X)
            elif mode == "interval":
                interval_host.pack(fill=tk.X)

        _sep()

        # ── Modules ────────────────────────────────────────────
        _lbl("MODULES TO SCAN")
        mod_frame = tk.Frame(wrap, bg=C["surface"])
        mod_frame.pack(fill=tk.X, pady=(4, 0))
        saved_mods = cfg.get("modules",
                             [m for m, *_ in _MODULES if m != "Baseline Diff"])
        sv_mods: dict[str, tk.BooleanVar] = {}
        cols = 2
        for idx, (mid, name, *_) in enumerate(_MODULES):
            if mid == "Baseline Diff":
                continue
            bv = tk.BooleanVar(value=(mid in saved_mods))
            sv_mods[mid] = bv
            cell = tk.Frame(mod_frame, bg=C["surface"])
            cell.grid(row=idx//cols, column=idx%cols, sticky="w", padx=(0,16), pady=2)
            box_m = tk.Label(cell, text="  ", width=2, bg=C["card"],
                             font=("Consolas", 8))
            box_m.pack(side=tk.LEFT)
            lbl_m = tk.Label(cell, text=name,
                             fg=C["muted"], bg=C["surface"],
                             font=("Segoe UI", 8))
            lbl_m.pack(side=tk.LEFT, padx=(4, 0))

            def _ref_m(b=box_m, l=lbl_m, v=bv, *_):
                b.configure(bg=C["green"] if v.get() else C["card"],
                            text="✓" if v.get() else "  ",
                            fg=C["bg"] if v.get() else C["card"])
                l.configure(fg=C["text"] if v.get() else C["muted"])
            bv.trace_add("write", _ref_m); _ref_m()
            for w in (cell, box_m, lbl_m):
                w.bind("<Button-1>", lambda _, v=bv: v.set(not v.get()))

        _sep()

        # ── Auto-email ─────────────────────────────────────────
        sv_ae = tk.BooleanVar(value=bool(cfg.get("auto_email", True)))
        ae_row = tk.Frame(wrap, bg=C["surface"])
        ae_row.pack(fill=tk.X)
        ae_box = tk.Label(ae_row, text="  ", width=2, bg=C["card"],
                          font=("Consolas", 8))
        ae_box.pack(side=tk.LEFT)
        ae_lbl = tk.Label(ae_row,
                          text=f"Auto-email report to {self._current_email or 'registered address'}",
                          fg=C["muted"], bg=C["surface"],
                          font=("Segoe UI", 9))
        ae_lbl.pack(side=tk.LEFT, padx=(8, 0))

        def _ref_ae(*_):
            ae_box.configure(bg=C["green"] if sv_ae.get() else C["card"],
                             text="✓" if sv_ae.get() else "  ",
                             fg=C["bg"] if sv_ae.get() else C["card"])
            ae_lbl.configure(fg=C["text"] if sv_ae.get() else C["muted"])
        sv_ae.trace_add("write", _ref_ae); _ref_ae()
        for w in (ae_row, ae_box, ae_lbl):
            w.bind("<Button-1>", lambda _: sv_ae.set(not sv_ae.get()))

        # ── Next-run preview ────────────────────────────────────
        nxt_lbl = tk.Label(wrap, text="", fg=C["faint"], bg=C["surface"],
                           font=("Segoe UI", 8))
        nxt_lbl.pack(anchor="w", pady=(8, 0))

        def _preview_next():
            if not sv_enabled.get():
                nxt_lbl.configure(text="Scheduling is disabled.")
                return
            try:
                hh = int(sv_hour.get()); mm = int(sv_min.get())
                time_s = f"{hh:02d}:{mm:02d}"
            except Exception:
                time_s = "09:00"
            active_days = [d for d, v in sv_days.items() if v.get()]
            try:
                ih = int(sv_interval.get())
            except Exception:
                ih = 6
            nxt = _next_run_for(sv_mode.get(), time_s, active_days, ih)
            nxt_lbl.configure(
                text=f"Next scan:  {nxt.strftime('%A, %d %b %Y  at  %H:%M')}",
                fg=C["green"])

        # ── Buttons ────────────────────────────────────────────
        btn_row = tk.Frame(dlg, bg=C["surface"])
        btn_row.pack(fill=tk.X, padx=28, pady=(0, 20))

        prev_btn = tk.Button(btn_row, text="Preview Next",
                             command=_preview_next,
                             bg=C["card2"], fg=C["text"],
                             activebackground=C["border"],
                             activeforeground=C["white"],
                             font=("Segoe UI", 9),
                             relief=tk.FLAT, bd=0,
                             padx=12, pady=6, cursor="hand2")
        prev_btn.pack(side=tk.LEFT)

        def _cancel(): dlg.destroy()

        def _save():
            try:
                hh = int(sv_hour.get()); mm = int(sv_min.get())
                time_s = f"{hh:02d}:{mm:02d}"
            except Exception:
                time_s = "09:00"
            active_days = [d for d, v in sv_days.items() if v.get()]
            try:
                ih = int(sv_interval.get())
            except Exception:
                ih = 6
            mods_sel = [mid for mid, v in sv_mods.items() if v.get()]
            if not mods_sel:
                messagebox.showwarning("No Modules",
                                       "Select at least one module to scan.",
                                       parent=dlg)
                return

            nxt = _next_run_for(sv_mode.get(), time_s, active_days, ih) \
                  if sv_enabled.get() else None

            self._sched_cfg = {
                "enabled":        sv_enabled.get(),
                "mode":           sv_mode.get(),
                "time":           time_s,
                "days":           active_days,
                "interval_hours": ih,
                "modules":        mods_sel,
                "auto_email":     sv_ae.get(),
                "next_run":       nxt.isoformat() if nxt else "",
            }
            self._sched_next = nxt
            self._save_user_schedule()

            # Update right-panel labels
            if sv_enabled.get() and nxt:
                self._sv_sched_status.set(self._sched_label(self._sched_cfg))
                self._sv_sched_next.set(nxt.strftime("%d %b  %H:%M"))
            else:
                self._sv_sched_status.set("Off")
                self._sv_sched_next.set("—")

            dlg.destroy()
            messagebox.showinfo(
                "Schedule Saved",
                f"Scheduled scan saved.\n\n"
                f"Next run:  {nxt.strftime('%A, %d %b %Y  at  %H:%M')}"
                if nxt else "Scheduling disabled.",
            )

        tk.Button(btn_row, text="Cancel", command=_cancel,
                  bg=C["surface"], fg=C["muted"],
                  activebackground=C["card"], activeforeground=C["text"],
                  font=("Segoe UI", 9), relief=tk.FLAT, bd=0,
                  padx=14, pady=6, cursor="hand2").pack(side=tk.RIGHT, padx=(8, 0))

        tk.Button(btn_row, text="Save Schedule", command=_save,
                  bg=C["green"], fg=C["bg"],
                  activebackground="#4ac760", activeforeground=C["bg"],
                  font=("Segoe UI", 9, "bold"),
                  relief=tk.FLAT, bd=0,
                  padx=14, pady=6, cursor="hand2").pack(side=tk.RIGHT)

        # Trigger initial mode-specific widget visibility
        _update_options()
        # Set the initial radio-button visual state
        sv_mode.trace_add("write", lambda *_: _update_options())
        _preview_next()

    def _show_howto(self):
        messagebox.showinfo(
            "How to Use ShieldScan",
            "QUICK START\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "1.  Select scan modules in the left panel.\n"
            "    All modules are on by default — recommended.\n\n"
            "2.  Click 'Run Scan' (top-right).\n"
            "    The scan takes 10–60 seconds.\n\n"
            "3.  Watch results appear in real time.\n"
            "    The Risk Meter on the right updates live.\n\n"
            "UNDERSTANDING RESULTS\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  HIGH   — Serious threat. Investigate immediately.\n"
            "  MED    — Suspicious. Worth reviewing.\n"
            "  LOW    — Minor anomaly. Likely safe.\n\n"
            "Risk Score:\n"
            "  0–15   = Clean\n"
            "  16–40  = Low Risk\n"
            "  41–60  = Suspicious\n"
            "  61–100 = Compromised\n\n"
            "TIPS\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "• Run as Administrator for the most complete scan.\n"
            "• Hover over any element for a tooltip explanation.\n"
            "• Use Tools → Capture Baseline before changes,\n"
            "  then enable 'Compare to Baseline' to see what changed.",
        )

    def _about(self):
        messagebox.showinfo(
            f"ShieldScan  {self.VERSION}",
            f"ShieldScan  {self.VERSION}\n\n"
            "A Windows security scanner for hidden processes,\n"
            "suspicious drivers, network anomalies, file integrity\n"
            "violations and persistence mechanisms.\n\n"
            "ML-powered threat classification with stacking ensemble.\n"
            "RAG-based false-positive suppression — 100% local.\n\n"
            "For defensive and educational use only.",
        )

    # ══════════════════════════════════════════════════════════
    # Email helpers
    # ══════════════════════════════════════════════════════════

    def _load_email_cfg(self) -> dict:
        cfg = dict(_ECFG_DEFAULTS)
        if os.path.exists(_ECFG):
            try:
                with open(_ECFG, encoding="utf-8") as f:
                    cfg.update(json.load(f))
            except Exception:
                pass
        return cfg

    def _save_email_cfg(self, cfg: dict):
        try:
            with open(_ECFG, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
        except Exception as exc:
            messagebox.showerror("Email Settings",
                                 f"Could not save settings:\n{exc}")

    def _send_report_email(self, report_path: str | None = None,
                           auto_recipient: str | None = None):
        """Show a confirm dialog (always asks From/To), then send inline HTML."""
        cfg = self._load_email_cfg()
        if not cfg.get("smtp_server"):
            if messagebox.askyesno(
                "Email Not Configured",
                "SMTP settings are not configured yet.\n\n"
                "Open Email Settings now?"
            ):
                self._email_settings_dialog()
            return

        r = report_path or self._last_report or self._find_report()
        if not r or not os.path.exists(r):
            messagebox.showwarning("No Report",
                                   "No HTML report found to send.\n"
                                   "Run a scan first.")
            return

        # ── Confirm dialog (shown every time) ─────────────────
        dlg = tk.Toplevel(self)
        dlg.title("Send Report by Email")
        dlg.configure(bg=C["surface"])
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.transient(self)

        hdr = tk.Frame(dlg, bg=C["card"])
        hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg=C["border"], height=1).pack(side=tk.BOTTOM, fill=tk.X)
        tk.Label(hdr, text="Send Report by Email",
                 fg=C["white"], bg=C["card"],
                 font=("Segoe UI", 11, "bold"),
                 padx=20, pady=12).pack(side=tk.LEFT)

        wrap = tk.Frame(dlg, bg=C["surface"])
        wrap.pack(fill=tk.BOTH, padx=32, pady=24)

        # ── Report info card ──────────────────────────────────
        try:
            fname = os.path.basename(r)
            ts = fname.replace("report_", "").replace(".html", "")
            dt_parsed = datetime.strptime(ts, "%Y%m%d_%H%M%S")
            rpt_label = dt_parsed.strftime("%d %b %Y  %H:%M:%S")
        except Exception:
            rpt_label = os.path.basename(r)

        info_f = tk.Frame(wrap, bg=C["card2"])
        info_f.pack(fill=tk.X, pady=(0, 20))
        tk.Label(info_f,
                 text=f"   📋  {rpt_label}",
                 fg=C["text"], bg=C["card2"],
                 font=("Segoe UI", 9), pady=10).pack(anchor="w")

        # ── Address fields ────────────────────────────────────
        def _field(label, default):
            outer_f = tk.Frame(wrap, bg=C["surface"])
            outer_f.pack(fill=tk.X, pady=8)
            tk.Label(outer_f, text=label,
                     fg=C["muted"], bg=C["surface"],
                     font=("Segoe UI", 9), width=8,
                     anchor="w").pack(side=tk.LEFT)
            e = tk.Entry(outer_f,
                         bg=C["card"], fg=C["text"],
                         insertbackground=C["text"],
                         relief=tk.FLAT, font=("Segoe UI", 9),
                         highlightthickness=1,
                         highlightcolor=C["green"],
                         highlightbackground=C["border"],
                         width=38)
            e.insert(0, default)
            e.pack(side=tk.LEFT, ipady=4)
            return e

        # Prefer: auto_recipient → registered user email → saved config recipient
        default_to = auto_recipient or self._current_email or cfg.get("recipient", "")
        e_to = _field("To:", default_to)

        # ── Security note ─────────────────────────────────────
        hint = tk.Frame(wrap, bg=C["card2"])
        hint.pack(fill=tk.X, pady=(16, 0))
        tk.Label(hint,
                 text="   ✔  Report renders directly in Gmail, Outlook and all major clients.\n"
                      "   ✔  Sent directly from your mail server — no third party involved.",
                 fg=C["muted"], bg=C["card2"],
                 font=("Segoe UI", 8), justify=tk.LEFT,
                 padx=4, pady=10).pack(anchor="w")

        status_lbl = tk.Label(wrap, text="",
                               fg=C["muted"], bg=C["surface"],
                               font=("Segoe UI", 8))
        status_lbl.pack(anchor="w", pady=(12, 0))

        sent = {"done": False}

        def _do_send(sender: str, recipient: str):
            try:
                # Read the HTML report
                with open(r, encoding="utf-8", errors="replace") as fh:
                    html_body = fh.read()

                # ── Extract findings for detailed plain-text ──
                findings_lines: list[str] = []
                try:
                    # Look for finding rows in the HTML (class="finding" or severity badges)
                    finding_blocks = re.findall(
                        r'<(?:div|tr)[^>]*class="[^"]*finding[^"]*"[^>]*>(.*?)</(?:div|tr)>',
                        html_body, re.S | re.I)
                    for blk in finding_blocks[:30]:  # cap at 30
                        text = re.sub(r'<[^>]+>', ' ', blk)
                        text = re.sub(r'\s+', ' ', text).strip()
                        if text:
                            findings_lines.append(f"  • {text[:200]}")
                except Exception:
                    pass

                findings_section = ""
                if findings_lines:
                    findings_section = (
                        f"\nDETAILED FINDINGS ({len(findings_lines)} shown)\n"
                        f"{'─' * 50}\n"
                        + "\n".join(findings_lines)
                        + "\n"
                    )

                def _int_label(key):
                    lbl = self._count_rows.get(key)
                    return lbl.cget("text") if lbl else "0"

                # Plain-text fallback summary with findings
                plain_body = (
                    f"ShieldScan  {self.VERSION}  —  Scan Report\n"
                    f"{'─' * 50}\n\n"
                    f"Date       : {rpt_label}\n"
                    f"User       : {self._current_user}\n"
                    f"Risk Score : {self._score}/100\n"
                    f"Verdict    : {self._verdict or 'See full report'}\n\n"
                    f"Findings   :  HIGH {_int_label('HIGH')}  "
                    f"MED {_int_label('MED')}  "
                    f"LOW {_int_label('LOW')}  "
                    f"(Total {_int_label('TOTAL')})\n"
                    f"{findings_section}\n"
                    f"{'─' * 50}\n"
                    f"Open the HTML version for the full interactive report.\n\n"
                    f"Generated by ShieldScan {self.VERSION}"
                )

                # Build multipart/alternative so clients render HTML inline
                msg = MIMEMultipart("alternative")
                msg["From"]    = sender
                msg["To"]      = recipient
                msg["Subject"] = (
                    f"ShieldScan — Scan Report  "
                    f"{datetime.now().strftime('%d %b %Y %H:%M')}"
                )
                msg.attach(MIMEText(plain_body, "plain", "utf-8"))
                msg.attach(MIMEText(html_body,  "html",  "utf-8"))

                ctx  = ssl.create_default_context()
                port = int(cfg.get("smtp_port", 587))
                if cfg.get("use_tls", True):
                    with smtplib.SMTP(cfg["smtp_server"], port) as s:
                        s.ehlo()
                        s.starttls(context=ctx)
                        s.login(cfg["username"], cfg["password"])
                        s.sendmail(sender, recipient, msg.as_string())
                else:
                    with smtplib.SMTP_SSL(
                            cfg["smtp_server"], port, context=ctx) as s:
                        s.login(cfg["username"], cfg["password"])
                        s.sendmail(sender, recipient, msg.as_string())

                self.after(0, lambda: (
                    dlg.destroy(),
                    messagebox.showinfo(
                        "Email Sent",
                        f"Report sent successfully to:\n{recipient}"),
                    self._sv_status.set("Email sent.")
                ))
            except Exception as exc:
                self.after(0, lambda e=exc: (
                    status_lbl.configure(
                        text=f"Send failed: {e}", fg=C["red"]),
                    send_btn.configure(state=tk.NORMAL,
                                       text="Send  ✉")
                ))

        def _send():
            sender    = cfg.get("username", "")
            recipient = e_to.get().strip()
            if not recipient or "@" not in recipient:
                status_lbl.configure(
                    text="Please enter a valid recipient email.", fg=C["yellow"])
                return
            send_btn.configure(state=tk.DISABLED, text="Sending…")
            status_lbl.configure(text="Connecting to SMTP server…",
                                  fg=C["muted"])
            dlg.update_idletasks()
            threading.Thread(
                target=_do_send, args=(sender, recipient), daemon=True
            ).start()
            self._sv_status.set("Sending email…")

        btn_row = tk.Frame(dlg, bg=C["surface"])
        btn_row.pack(fill=tk.X, padx=32, pady=(0, 28))

        tk.Button(btn_row, text="Cancel", command=dlg.destroy,
                  bg=C["surface"], fg=C["muted"],
                  activebackground=C["card"], activeforeground=C["text"],
                  font=("Segoe UI", 9), relief=tk.FLAT, bd=0,
                  padx=14, pady=8, cursor="hand2").pack(side=tk.RIGHT, padx=(8, 0))

        send_btn = tk.Button(btn_row, text="Send  ✉", command=_send,
                             bg=C["green"], fg=C["bg"],
                             activebackground="#4ac760",
                             activeforeground=C["bg"],
                             font=("Segoe UI", 9, "bold"),
                             relief=tk.FLAT, bd=0,
                             padx=16, pady=6, cursor="hand2")
        send_btn.pack(side=tk.RIGHT)

    def _email_settings_dialog(self):
        dlg = tk.Toplevel(self)
        dlg.title("Email Settings")
        dlg.configure(bg=C["surface"])
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.transient(self)

        cfg = self._load_email_cfg()

        # ── Header ────────────────────────────────────────────
        hdr = tk.Frame(dlg, bg=C["card"])
        hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg=C["border"], height=1).pack(
            side=tk.BOTTOM, fill=tk.X)
        tk.Label(hdr, text="Email Settings",
                 fg=C["white"], bg=C["card"],
                 font=("Segoe UI", 11, "bold"),
                 padx=20, pady=12).pack(side=tk.LEFT)

        wrap = tk.Frame(dlg, bg=C["surface"])
        wrap.pack(fill=tk.BOTH, padx=24, pady=16)

        # ── Preset picker ─────────────────────────────────────
        presets = {
            "Gmail":       ("smtp.gmail.com",      587, True),
            "Outlook/M365":("smtp.office365.com",  587, True),
            "Yahoo":       ("smtp.mail.yahoo.com", 587, True),
            "Custom":      ("",                    587, True),
        }

        prow = tk.Frame(wrap, bg=C["surface"])
        prow.pack(fill=tk.X, pady=(0, 12))
        tk.Label(prow, text="Quick Setup:",
                 fg=C["muted"], bg=C["surface"],
                 font=("Segoe UI", 9)).pack(side=tk.LEFT)

        sv_preset = tk.StringVar(value="Custom")
        entries_refs: dict = {}   # populated below

        def _apply_preset(p: str):
            if p not in presets: return
            s, port, tls = presets[p]
            if s:
                entries_refs["smtp_server"].delete(0, tk.END)
                entries_refs["smtp_server"].insert(0, s)
                entries_refs["smtp_port"].delete(0, tk.END)
                entries_refs["smtp_port"].insert(0, str(port))
                sv_tls.set(tls)

        for preset_name in presets:
            b = tk.Button(prow, text=preset_name,
                          command=lambda p=preset_name: (
                              sv_preset.set(p), _apply_preset(p)),
                          bg=C["card"], fg=C["muted"],
                          activebackground=C["card2"],
                          activeforeground=C["text"],
                          font=("Segoe UI", 8),
                          relief=tk.FLAT, bd=0,
                          padx=10, pady=3, cursor="hand2")
            b.pack(side=tk.LEFT, padx=(8, 0))
            b.bind("<Enter>", lambda _, w=b: w.configure(fg=C["text"]))
            b.bind("<Leave>", lambda _, w=b: w.configure(fg=C["muted"]))

        # ── Form fields ───────────────────────────────────────
        def _field(label: str, key: str, default: str,
                   show: str = "") -> tk.Entry:
            f = tk.Frame(wrap, bg=C["surface"])
            f.pack(fill=tk.X, pady=5)
            tk.Label(f, text=label, fg=C["muted"], bg=C["surface"],
                     font=("Segoe UI", 9), width=16,
                     anchor="w").pack(side=tk.LEFT)
            e = tk.Entry(f, bg=C["card"], fg=C["text"],
                         insertbackground=C["text"],
                         relief=tk.FLAT,
                         font=("Segoe UI", 9),
                         highlightthickness=1,
                         highlightcolor=C["green"],
                         highlightbackground=C["border"],
                         show=show, width=32)
            e.insert(0, str(cfg.get(key, default)))
            e.pack(side=tk.LEFT)
            entries_refs[key] = e
            return e

        _field("SMTP Server",  "smtp_server", _ECFG_DEFAULTS["smtp_server"])
        _field("Port",         "smtp_port",   str(_ECFG_DEFAULTS["smtp_port"]))
        _field("Your Email",   "username",    "")
        _field("Password",     "password",    "", show="●")
        _field("Send To",      "recipient",   "")

        sv_tls = tk.BooleanVar(value=bool(cfg.get("use_tls", True)))
        tls_f  = tk.Frame(wrap, bg=C["surface"])
        tls_f.pack(fill=tk.X, pady=5)
        tk.Label(tls_f, text="", width=16, bg=C["surface"]).pack(side=tk.LEFT)
        self._optrow_dlg(tls_f, "Use TLS (recommended)", sv_tls)

        # ── Gmail hint ────────────────────────────────────────
        hint = tk.Frame(wrap, bg=C["card2"])
        hint.pack(fill=tk.X, pady=(12, 0))
        tk.Label(hint,
                 text="ℹ  For Gmail, use an App Password — not your regular password.\n"
                      "   myaccount.google.com → Security → App Passwords",
                 fg=C["muted"], bg=C["card2"],
                 font=("Segoe UI", 8), justify=tk.LEFT,
                 padx=12, pady=8).pack(anchor="w")

        # ── Buttons ───────────────────────────────────────────
        btn_row = tk.Frame(dlg, bg=C["surface"])
        btn_row.pack(fill=tk.X, padx=24, pady=(0, 20))

        status_lbl = tk.Label(btn_row, text="",
                               fg=C["muted"], bg=C["surface"],
                               font=("Segoe UI", 8))
        status_lbl.pack(side=tk.LEFT)

        def _save():
            new_cfg = {
                "smtp_server": entries_refs["smtp_server"].get().strip(),
                "smtp_port":   int(entries_refs["smtp_port"].get().strip() or 587),
                "username":    entries_refs["username"].get().strip(),
                "password":    entries_refs["password"].get(),
                "recipient":   entries_refs["recipient"].get().strip(),
                "use_tls":     sv_tls.get(),
            }
            self._save_email_cfg(new_cfg)
            dlg.destroy()

        def _test():
            status_lbl.configure(text="Testing…", fg=C["muted"])
            dlg.update_idletasks()
            try:
                ctx = ssl.create_default_context()
                port = int(entries_refs["smtp_port"].get().strip() or 587)
                srv  = entries_refs["smtp_server"].get().strip()
                usr  = entries_refs["username"].get().strip()
                pwd  = entries_refs["password"].get()
                if sv_tls.get():
                    with smtplib.SMTP(srv, port) as s:
                        s.ehlo(); s.starttls(context=ctx); s.login(usr, pwd)
                else:
                    with smtplib.SMTP_SSL(srv, port, context=ctx) as s:
                        s.login(usr, pwd)
                status_lbl.configure(text="✓ Connection successful",
                                     fg=C["green"])
            except Exception as exc:
                status_lbl.configure(text=f"✗ {exc}", fg=C["red"])

        for txt, cmd, fg, bg in (
            ("Test Connection", _test, C["text"],  C["card2"]),
            ("Save",            _save, C["bg"],    C["green"]),
            ("Cancel",          dlg.destroy, C["muted"], C["surface"]),
        ):
            b = tk.Button(btn_row, text=txt, command=cmd,
                          bg=bg, fg=fg,
                          activebackground=C["card2"],
                          activeforeground=C["white"],
                          font=("Segoe UI", 9),
                          relief=tk.FLAT, bd=0,
                          padx=14, pady=6, cursor="hand2")
            b.pack(side=tk.RIGHT, padx=(6, 0))

    def _optrow_dlg(self, parent, label: str, var: tk.BooleanVar):
        """Checkbox row for use inside dialogs."""
        box = tk.Label(parent, text="  ", width=2, bg=C["card"],
                       font=("Consolas", 8))
        box.pack(side=tk.LEFT)
        lbl = tk.Label(parent, text=label, fg=C["muted"], bg=C["surface"],
                       font=("Segoe UI", 9))
        lbl.pack(side=tk.LEFT, padx=(8, 0))

        def _ref(*_):
            if var.get():
                box.configure(bg=C["green"], text="✓", fg=C["bg"])
                lbl.configure(fg=C["text"])
            else:
                box.configure(bg=C["card"], text="  ", fg=C["card"])
                lbl.configure(fg=C["muted"])
        var.trace_add("write", _ref); _ref()
        for w in (box, lbl):
            w.bind("<Button-1>", lambda _: var.set(not var.get()))


# ══════════════════════════════════════════════════════════════════════════
# Login / Register window
# ══════════════════════════════════════════════════════════════════════════

class LoginWindow(tk.Tk):
    """
    Landscape sign-in / register window (780 × auto-height).
    The form column is 340 px wide; ~220 px of blank space flanks each side.
    """

    _WIN_W  = 780   # fixed window width
    _FORM_W = 340   # form column width  →  side margins = (780-340)/2 = 220 px

    def __init__(self):
        super().__init__()
        self._result: tuple[str, str] | None = None
        self.title("ShieldScan — Sign In")
        self.configure(bg=C["bg"])
        self.resizable(False, False)

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            pass

        # Dark title bar
        try:
            self.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            if hwnd:
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, 20, ctypes.byref(ctypes.c_int(1)),
                    ctypes.sizeof(ctypes.c_int))
        except Exception:
            pass

        self._mode = tk.StringVar(value="login")
        self._entries: dict[str, tk.Entry] = {}
        self._sv_status = tk.StringVar(value="")
        self._build()
        self._center()

    # ── Layout helpers ─────────────────────────────────────────────────────

    def _center(self):
        """Set geometry to fixed width, content height, centered on screen."""
        self.update_idletasks()
        h  = self.winfo_reqheight()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x  = (sw - self._WIN_W) // 2
        y  = (sh - h) // 2
        self.geometry(f"{self._WIN_W}x{h}+{x}+{y}")

    def _side_pad(self) -> int:
        """Horizontal padding so the form column is centered."""
        return (self._WIN_W - self._FORM_W) // 2

    # ── Build ──────────────────────────────────────────────────────────────

    def _build(self):
        px = self._side_pad()   # ~220 px blank on each side

        # ── Top bar: full-width surface strip ──────────────────
        topbar = tk.Frame(self, bg=C["surface"])
        topbar.pack(fill=tk.X)
        tk.Frame(topbar, bg=C["border"], height=1).pack(side=tk.BOTTOM, fill=tk.X)

        logo = tk.Frame(topbar, bg=C["surface"])
        logo.pack(side=tk.LEFT, padx=px, pady=14)
        tk.Label(logo, text="🛡 ", bg=C["surface"],
                 font=("Segoe UI", 17)).pack(side=tk.LEFT)
        tk.Label(logo, text="Shield", fg=C["white"], bg=C["surface"],
                 font=("Segoe UI", 15, "bold")).pack(side=tk.LEFT)
        tk.Label(logo, text="Scan", fg=C["green"], bg=C["surface"],
                 font=("Segoe UI", 15, "bold")).pack(side=tk.LEFT)

        right_block = tk.Frame(topbar, bg=C["surface"])
        right_block.pack(side=tk.RIGHT, padx=px, pady=12)
        tk.Label(right_block, text="Secure. Local. Private.",
                 fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 8)).pack(anchor="e")
        tk.Label(right_block, text="v2.0  —  Enterprise Edition",
                 fg=C["faint"], bg=C["surface"],
                 font=("Segoe UI", 7)).pack(anchor="e", pady=(1, 0))

        # ── Card container (centered column) ───────────────────
        card_outer = tk.Frame(self, bg=C["border"])
        card_outer.pack(padx=px, pady=(22, 0), fill=tk.X)
        tk.Frame(card_outer, bg=C["green"], height=3).pack(fill=tk.X)
        card = tk.Frame(card_outer, bg=C["card"])
        card.pack(fill=tk.X)
        tk.Frame(card_outer, bg=C["border"], height=1).pack(fill=tk.X, side=tk.BOTTOM)

        # ── Mode tabs inside card ──────────────────────────────
        toggle = tk.Frame(card, bg=C["card2"])
        toggle.pack(fill=tk.X)
        for mode, label in (("login", "  Sign In  "), ("register", "  Create Account  ")):
            b = tk.Button(toggle, text=label,
                          command=lambda m=mode: self._switch_mode(m),
                          bg=C["card2"], fg=C["muted"],
                          activebackground=C["card"],
                          activeforeground=C["white"],
                          font=("Segoe UI", 9, "bold"),
                          relief=tk.FLAT, bd=0,
                          padx=16, pady=11, cursor="hand2")
            b.pack(side=tk.LEFT, expand=True, fill=tk.X)
            setattr(self, f"_btn_{mode}", b)
        tk.Frame(card, bg=C["border"], height=1).pack(fill=tk.X)

        # ── Form area (rebuilt on mode switch) ─────────────────
        self._form_host = tk.Frame(card, bg=C["card"])
        self._form_host.pack(fill=tk.X, padx=20, pady=(14, 0))

        # Status / error label
        self._lbl_status = tk.Label(card, textvariable=self._sv_status,
                                     fg=C["red"], bg=C["card"],
                                     font=("Segoe UI", 8),
                                     wraplength=self._FORM_W, justify=tk.LEFT)
        self._lbl_status.pack(padx=20, pady=(4, 0), anchor="w")

        # Submit button
        tk.Frame(card, bg=C["border"], height=1).pack(fill=tk.X, padx=20)
        self._submit_btn = tk.Button(card, text="Sign In",
                                      command=self._submit,
                                      bg=C["green"], fg=C["bg"],
                                      activebackground="#4ac760",
                                      activeforeground=C["bg"],
                                      font=("Segoe UI", 10, "bold"),
                                      relief=tk.FLAT, bd=0,
                                      pady=13, cursor="hand2")
        self._submit_btn.pack(padx=20, pady=(12, 20), fill=tk.X)

        foot_row = tk.Frame(self, bg=C["bg"])
        foot_row.pack(pady=(10, 24))
        tk.Label(foot_row, text="🔒 ", bg=C["bg"],
                 font=("Segoe UI", 8)).pack(side=tk.LEFT)
        tk.Label(foot_row,
                 text="All data stays on this device — no servers, no telemetry.",
                 fg=C["faint"], bg=C["bg"],
                 font=("Segoe UI", 7)).pack(side=tk.LEFT)

        self._switch_mode("login")

    def _entry(self, parent, label: str, key: str, show: str = ""):
        f = tk.Frame(parent, bg=C["card"])
        f.pack(fill=tk.X, pady=5)
        lbl = tk.Label(f, text=label, fg=C["muted"], bg=C["card"],
                       font=("Segoe UI", 8), anchor="w")
        lbl.pack(fill=tk.X)
        e = tk.Entry(f, bg=C["card2"], fg=C["text"],
                     insertbackground=C["text"],
                     relief=tk.FLAT, font=("Segoe UI", 10),
                     highlightthickness=1,
                     highlightcolor=C["green"],
                     highlightbackground=C["border"],
                     show=show)
        e.pack(fill=tk.X, ipady=9)
        e.bind("<Return>",   lambda _: self._submit())
        e.bind("<FocusIn>",  lambda _, l=lbl: l.configure(fg=C["green"]))
        e.bind("<FocusOut>", lambda _, l=lbl: l.configure(fg=C["muted"]))
        self._entries[key] = e
        return e

    def _switch_mode(self, mode: str):
        self._mode.set(mode)

        # Tab highlight
        for m in ("login", "register"):
            btn = getattr(self, f"_btn_{m}")
            if m == mode:
                btn.configure(fg=C["white"], bg=C["card2"])
                # green underline
                tk.Frame(btn, bg=C["green"], height=2).place(
                    relx=0, rely=1.0, relwidth=1.0, anchor="sw")
            else:
                btn.configure(fg=C["muted"], bg=C["card"])

        # Rebuild form fields
        for w in self._form_host.winfo_children():
            w.destroy()
        self._entries.clear()
        self._sv_status.set("")

        if mode == "login":
            self._entry(self._form_host, "Username", "username")
            self._entry(self._form_host, "Password", "password", show="●")
            fp_row = tk.Frame(self._form_host, bg=C["card"])
            fp_row.pack(fill=tk.X, pady=(2, 0))
            fp_lbl = tk.Label(fp_row, text="Forgot password?",
                              fg=C["muted"], bg=C["card"],
                              font=("Segoe UI", 8, "underline"),
                              cursor="hand2")
            fp_lbl.pack(side=tk.RIGHT, pady=2)
            fp_lbl.bind("<Button-1>", lambda _: self._forgot_password())
            fp_lbl.bind("<Enter>",    lambda _: fp_lbl.configure(fg=C["green"]))
            fp_lbl.bind("<Leave>",    lambda _: fp_lbl.configure(fg=C["muted"]))
            self._submit_btn.configure(text="Sign In")
        else:
            # 2-column grid for register keeps height similar to login
            grid = tk.Frame(self._form_host, bg=C["card"])
            grid.pack(fill=tk.X)
            grid.columnconfigure(0, weight=1)
            grid.columnconfigure(1, weight=1)

            def _grid_entry(label, key, row, col, show=""):
                cell = tk.Frame(grid, bg=C["card"])
                cell.grid(row=row, column=col, sticky="ew",
                          padx=(0, 8) if col == 0 else (8, 0), pady=5)
                tk.Label(cell, text=label, fg=C["muted"], bg=C["card"],
                         font=("Segoe UI", 8), anchor="w").pack(fill=tk.X)
                e = tk.Entry(cell, bg=C["card2"], fg=C["text"],
                             insertbackground=C["text"],
                             relief=tk.FLAT, font=("Segoe UI", 10),
                             highlightthickness=1,
                             highlightcolor=C["green"],
                             highlightbackground=C["border"],
                             show=show)
                e.pack(fill=tk.X, ipady=8)
                e.bind("<Return>", lambda _: self._submit())
                self._entries[key] = e

            _grid_entry("Username",            "username", 0, 0)
            _grid_entry("Email Address",        "email",    0, 1)
            _grid_entry("Password (min 6 chars)","password", 1, 0, show="●")
            _grid_entry("Confirm Password",     "confirm",  1, 1, show="●")
            self._submit_btn.configure(text="Create Account")

        # Focus first entry
        first = list(self._entries.values())
        if first:
            first[0].focus_set()

        # Re-center after height changes
        self.after(10, self._center)

    def _submit(self):
        self._sv_status.set("")
        mode = self._mode.get()

        def _get(key): return self._entries.get(key, type("e", (), {"get": lambda _: ""})()).get()

        username = _get("username").strip()
        password = _get("password")

        if mode == "login":
            user = _authenticate(username, password)
            if user:
                self._result = (user["username"], user["email"])
                self.destroy()
            else:
                self._sv_status.set("Invalid username or password.")

        else:
            email   = _get("email").strip()
            confirm = _get("confirm")
            if password != confirm:
                self._sv_status.set("Passwords do not match.")
                return
            err = _register_user(username, email, password)
            if err:
                self._sv_status.set(err)
            else:
                self._result = (username, email.lower())
                messagebox.showinfo(
                    "Account Created",
                    f"Welcome to ShieldScan, {username}!\n\n"
                    f"Scan reports will be sent to:\n{email}",
                    parent=self,
                )
                self.destroy()

    def _forgot_password(self):
        """Reset-password dialog (local only)."""
        dlg = tk.Toplevel(self)
        dlg.title("Reset Password")
        dlg.configure(bg=C["bg"])
        dlg.resizable(False, False)
        dlg.grab_set()

        self.update_idletasks()
        px = self.winfo_x() + (self.winfo_width()  - 360) // 2
        py = self.winfo_y() + (self.winfo_height() - 300) // 2
        dlg.geometry(f"360x300+{px}+{py}")

        hdr = tk.Frame(dlg, bg=C["surface"])
        hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg=C["green"], height=3).pack(fill=tk.X)
        tk.Label(hdr, text="Reset Your Password",
                 fg=C["white"], bg=C["surface"],
                 font=("Segoe UI", 12, "bold")).pack(padx=20, pady=(14, 4), anchor="w")
        tk.Label(hdr, text="Enter your username and a new password.",
                 fg=C["muted"], bg=C["surface"],
                 font=("Segoe UI", 8)).pack(padx=20, pady=(0, 12), anchor="w")
        tk.Frame(hdr, bg=C["border"], height=1).pack(fill=tk.X)

        body = tk.Frame(dlg, bg=C["bg"])
        body.pack(fill=tk.BOTH, expand=True, padx=24, pady=16)

        sv_err = tk.StringVar()

        def _lbl(text):
            tk.Label(body, text=text, fg=C["muted"], bg=C["bg"],
                     font=("Segoe UI", 8), anchor="w").pack(fill=tk.X, pady=(8, 1))

        def _ent(show=""):
            e = tk.Entry(body, bg=C["card2"], fg=C["text"],
                         insertbackground=C["text"], relief=tk.FLAT,
                         font=("Segoe UI", 10), highlightthickness=1,
                         highlightcolor=C["green"], highlightbackground=C["border"],
                         show=show)
            e.pack(fill=tk.X, ipady=7)
            return e

        _lbl("Username")
        e_user = _ent()
        _lbl("New Password  (min 6 chars)")
        e_pw1  = _ent(show="●")
        _lbl("Confirm New Password")
        e_pw2  = _ent(show="●")

        tk.Label(body, textvariable=sv_err, fg=C["red"], bg=C["bg"],
                 font=("Segoe UI", 8), wraplength=310,
                 justify=tk.LEFT).pack(anchor="w", pady=(6, 0))

        def _do_reset():
            uname = e_user.get().strip()
            pw1   = e_pw1.get()
            pw2   = e_pw2.get()
            sv_err.set("")
            if not uname:
                sv_err.set("Please enter your username."); return
            if len(pw1) < 6:
                sv_err.set("Password must be at least 6 characters."); return
            if pw1 != pw2:
                sv_err.set("Passwords do not match."); return
            users  = _load_users()
            target = next((u for u in users
                           if u.get("username","").lower() == uname.lower()), None)
            if target is None:
                sv_err.set("Username not found."); return
            target["password_hash"] = _hash_pw(pw1)
            _save_users(users)
            dlg.destroy()
            messagebox.showinfo("Password Reset",
                                f"Password for '{target['username']}' has been reset.\n"
                                "You can now sign in with your new password.",
                                parent=self)

        tk.Button(dlg, text="Reset Password", command=_do_reset,
                  bg=C["green"], fg=C["bg"], activebackground="#4ac760",
                  activeforeground=C["bg"], font=("Segoe UI", 10, "bold"),
                  relief=tk.FLAT, bd=0, pady=9,
                  cursor="hand2").pack(fill=tk.X, padx=24, pady=(0, 18))

        e_user.focus_set()
        e_pw1.bind("<Return>", lambda _: e_pw2.focus_set())
        e_pw2.bind("<Return>", lambda _: _do_reset())

    def run(self) -> tuple[str, str] | None:
        self.mainloop()
        return self._result


# ══════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════

def main():
    # ── Check for pre-authenticated relaunch (admin elevation path) ────────
    skip_login_once = "--skip-login" in sys.argv
    if skip_login_once:
        try:
            idx = sys.argv.index("--skip-login")
            raw = base64.b64decode(sys.argv[idx + 1]).decode("utf-8")
            username, email = raw.split("\x00", 1)
        except Exception:
            username, email = "Guest", ""
    else:
        username, email = "", ""

    while True:
        if not skip_login_once:
            # ── Normal path: show Login/Register window ───────────────────
            login_win = LoginWindow()
            result    = login_win.run()
            if result is None:
                return   # user closed window without signing in
            username, email = result

        skip_login_once = False   # only skip once per process lifetime

        # ── Admin check ───────────────────────────────────────────────────
        if not _is_admin() and "--no-admin-check" not in sys.argv:
            _tmp = tk.Tk();  _tmp.withdraw()
            ans = messagebox.askyesno(
                "Run as Administrator?",
                "ShieldScan works best with Administrator privileges.\n\n"
                "Without them, driver/registry/memory scans will have limited access.\n\n"
                "Restart as Administrator now?",
            )
            _tmp.destroy()
            if ans:
                encoded = base64.b64encode(
                    f"{username}\x00{email}".encode("utf-8")
                ).decode("ascii")
                script = os.path.abspath(__file__)
                args   = f'"{script}" --skip-login {encoded}'
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, args, None, 1)
                sys.exit(0)
                return

        app = App(username, email)
        app.mainloop()

        # Theme change → restart App with same user (no login)
        if app._restart_requested:
            # Reload global C from newly-saved config and refresh verdict colours
            global C, _VERDICT_COLOR
            C = dict(_THEMES[_current_theme_name()])
            _VERDICT_COLOR = _build_verdict_color()
            skip_login_once = True
            sys.argv.append("--no-admin-check")  # suppress re-prompt on theme switch
            continue

        # User logged out → loop back to show login window
        if app._logout_requested:
            continue

        break


if __name__ == "__main__":
    main()
