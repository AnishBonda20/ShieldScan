"""
Baseline snapshot manager.

Captures a point-in-time snapshot of the running system (processes,
drivers, network ports, autorun registry keys) and compares a later
scan against it to surface NEW items (new processes, new autoruns, etc.)
that appeared after the baseline was taken.

CLI (via main.py):
  python main.py --baseline            # capture a fresh baseline
  python main.py --diff                # run scans + diff against latest baseline
  python main.py --list-baselines      # list all saved baselines

Snapshots are stored in:  logs/baselines/baseline_YYYYMMDD_HHMMSS.json
"""

from __future__ import annotations

import os
import re
import json
import hashlib
import logging
import subprocess
import psutil
import winreg
from datetime import datetime

log = logging.getLogger(__name__)

_HERE     = os.path.dirname(os.path.abspath(__file__))
_BASE_DIR = os.path.join(_HERE, "logs", "baselines")


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _sha256_exe(path: str) -> str:
    if not path:
        return ""
    import hashlib
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(131072), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


# -----------------------------------------------------------------------
# System state collectors
# -----------------------------------------------------------------------

def _collect_processes() -> dict[str, dict]:
    procs: dict[str, dict] = {}
    for p in psutil.process_iter(["pid", "name", "exe", "username"]):
        try:
            info = p.info
            pid  = str(info["pid"])
            exe  = info.get("exe") or ""
            procs[pid] = {
                "name": info.get("name") or "",
                "exe":  exe,
                "hash": _sha256_exe(exe),
                "user": info.get("username") or "",
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return procs


def _collect_drivers() -> list[str]:
    names: list[str] = []
    try:
        out = subprocess.check_output(
            ["sc", "query", "type=", "driver", "state=", "all"],
            stderr=subprocess.DEVNULL, timeout=30, text=True,
        )
        names = re.findall(r"SERVICE_NAME:\s+(\S+)", out)
    except Exception as exc:
        log.debug("Baseline driver collect failed: %s", exc)
    return sorted(names)


def _collect_ports() -> list[dict]:
    ports: list[dict] = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.laddr:
                ports.append({
                    "port":   c.laddr.port,
                    "pid":    c.pid or 0,
                    "status": c.status,
                })
    except Exception as exc:
        log.debug("Baseline port collect failed: %s", exc)
    return ports


def _collect_autoruns() -> list[str]:
    entries: list[str] = []
    run_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, path in run_keys:
        try:
            with winreg.OpenKey(hive, path) as k:
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(k, i)
                        entries.append(f"{path}\\{name} -> {data}")
                        i += 1
                    except OSError:
                        break
        except OSError:
            pass
    return sorted(entries)


def _collect_services() -> list[str]:
    names: list[str] = []
    try:
        svc_key = r"SYSTEM\CurrentControlSet\Services"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, svc_key) as root:
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(root, i))
                    i += 1
                except OSError:
                    break
    except Exception as exc:
        log.debug("Baseline service collect failed: %s", exc)
    return sorted(names)


# -----------------------------------------------------------------------
# Snapshot capture
# -----------------------------------------------------------------------

def capture() -> dict:
    """Capture a full system-state snapshot and write it to disk."""
    os.makedirs(_BASE_DIR, exist_ok=True)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    snap: dict = {
        "captured_at": datetime.now().isoformat(),
        "processes":   _collect_processes(),
        "drivers":     _collect_drivers(),
        "ports":       _collect_ports(),
        "autoruns":    _collect_autoruns(),
        "services":    _collect_services(),
    }
    path = os.path.join(_BASE_DIR, f"baseline_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snap, f, indent=2)
    snap["_path"] = path
    log.info("Baseline saved: %s (%d procs, %d autoruns, %d services)",
             path, len(snap["processes"]), len(snap["autoruns"]), len(snap["services"]))
    return snap


# -----------------------------------------------------------------------
# Baseline access
# -----------------------------------------------------------------------

def load_latest() -> dict | None:
    """Return the most recent baseline snapshot, or None."""
    if not os.path.isdir(_BASE_DIR):
        return None
    files = sorted(
        [f for f in os.listdir(_BASE_DIR)
         if f.startswith("baseline_") and f.endswith(".json")],
        reverse=True,
    )
    if not files:
        return None
    path = os.path.join(_BASE_DIR, files[0])
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        data["_path"] = path
        log.info("Loaded baseline: %s", path)
        return data
    except Exception as exc:
        log.warning("Failed to load baseline %s: %s", path, exc)
        return None


def list_baselines() -> list[str]:
    """Return sorted list of saved baseline filenames (newest first)."""
    if not os.path.isdir(_BASE_DIR):
        return []
    return sorted(
        [f for f in os.listdir(_BASE_DIR)
         if f.startswith("baseline_") and f.endswith(".json")],
        reverse=True,
    )


# -----------------------------------------------------------------------
# Differential analysis
# -----------------------------------------------------------------------

def diff(baseline: dict) -> list[dict]:
    """
    Compare current system state against a baseline snapshot.
    Returns findings for items that appeared or changed since the baseline.
    """
    findings: list[dict] = []
    now_procs    = _collect_processes()
    now_autoruns = set(_collect_autoruns())
    now_services = set(_collect_services())

    bl_procs     = baseline.get("processes", {})
    bl_autoruns  = set(baseline.get("autoruns", []))
    bl_services  = set(baseline.get("services", []))

    # Build lookup: (name.lower, exe.lower) -> True  for processes in baseline
    bl_name_exe = {
        (v["name"].lower(), v["exe"].lower())
        for v in bl_procs.values()
        if v.get("name")
    }

    # Build exe -> hash map from baseline for tamper detection
    bl_exe_hash: dict[str, str] = {
        v["exe"].lower(): v["hash"]
        for v in bl_procs.values()
        if v.get("exe") and v.get("hash")
    }

    # --- New processes not in baseline ---
    for pid, info in now_procs.items():
        name = info.get("name", "")
        exe  = info.get("exe", "")
        if not name:
            continue
        key = (name.lower(), exe.lower())
        if key not in bl_name_exe:
            findings.append({
                "severity": "MEDIUM",
                "reason":   f"Baseline diff: new process since snapshot — '{name}' (PID {pid}) at {exe or '?'}",
                "pid":      int(pid),
                "name":     name,
            })

    # --- Tampered process executables (same exe path, different hash) ---
    for info in now_procs.values():
        exe  = info.get("exe", "")
        h    = info.get("hash", "")
        name = info.get("name", "")
        if not exe or not h:
            continue
        bl_h = bl_exe_hash.get(exe.lower())
        if bl_h and bl_h != h:
            findings.append({
                "severity": "HIGH",
                "reason":   f"Baseline diff: process binary CHANGED since snapshot — '{name}' at {exe}",
                "name":     name,
            })

    # --- New autorun entries ---
    for entry in sorted(now_autoruns - bl_autoruns):
        findings.append({
            "severity": "HIGH",
            "reason":   f"Baseline diff: new autorun entry since snapshot — {entry}",
            "name":     entry.split("\\")[-1].split("->")[0].strip(),
        })

    # --- Removed autorun entries (less critical, but informational) ---
    for entry in sorted(bl_autoruns - now_autoruns):
        findings.append({
            "severity": "LOW",
            "reason":   f"Baseline diff: autorun entry removed since snapshot — {entry}",
            "name":     entry.split("\\")[-1].split("->")[0].strip(),
        })

    # --- New services ---
    for svc in sorted(now_services - bl_services):
        findings.append({
            "severity": "MEDIUM",
            "reason":   f"Baseline diff: new Windows service installed since snapshot — '{svc}'",
            "name":     svc,
        })

    log.info("Baseline diff: %d change(s) detected", len(findings))
    return findings
