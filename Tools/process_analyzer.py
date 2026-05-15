"""
Cross-view process analysis.

Compares three independent process lists:
  1. psutil  (uses Windows NtQuerySystemInformation)
  2. WMIC    (WMI — separate code path)
  3. tasklist (Win32 API)

A PID consistently missing from one source is a rootkit indicator.
Ephemeral processes that spawn/die between queries are filtered out
by doing a second confirmation pass before flagging.
"""

import subprocess
import logging
import re
import time
import psutil

log = logging.getLogger(__name__)

# Ephemeral port range — PIDs in this numeric range are more likely short-lived
# system processes (e.g. conhost instances launched per-command).
# We confirm suspicious PIDs with a second psutil check before flagging.

# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def _pids_from_psutil() -> set[int]:
    return {p.pid for p in psutil.process_iter(["pid"])}


def _pids_from_wmic() -> set[int]:
    try:
        out = subprocess.check_output(
            ["wmic", "process", "get", "ProcessId"],
            stderr=subprocess.DEVNULL, timeout=30, text=True,
        )
        return {int(m) for m in re.findall(r"\b(\d+)\b", out)}
    except Exception as exc:
        log.debug("WMIC query failed: %s", exc)
        return set()


def _pids_from_tasklist() -> set[int]:
    try:
        out = subprocess.check_output(
            ["tasklist", "/fo", "csv", "/nh"],
            stderr=subprocess.DEVNULL, timeout=30, text=True,
        )
        pids = set()
        for line in out.splitlines():
            parts = line.split(",")
            if len(parts) >= 2:
                try:
                    pids.add(int(parts[1].strip().strip('"')))
                except ValueError:
                    pass
        return pids
    except Exception as exc:
        log.debug("tasklist query failed: %s", exc)
        return set()


# ---------------------------------------------------------------------------
# Cross-view hidden process detection
# ---------------------------------------------------------------------------

def find_hidden_processes() -> list[dict]:
    """
    Compare psutil, WMIC, and tasklist. Flag genuine discrepancies only.

    Ephemeral processes (spawned and died between the two queries) are
    filtered by a short confirmation delay: a PID reported by WMIC/tasklist
    but absent from psutil is only flagged if it is STILL absent after a
    brief re-query — ephemeral processes will have exited by then.
    """
    # First snapshot
    psutil_snap1  = _pids_from_psutil()
    wmic_pids     = _pids_from_wmic()
    tasklist_pids = _pids_from_tasklist()

    findings = []

    # --- psutil has PID but WMIC/tasklist don't (psutil shows hidden process) ---
    for pid in psutil_snap1:
        missing_from = []
        if wmic_pids and pid not in wmic_pids:
            missing_from.append("WMIC")
        if tasklist_pids and pid not in tasklist_pids:
            missing_from.append("tasklist")
        if not missing_from:
            continue
        # Confirm: process must still be alive in psutil right now
        try:
            name = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue  # already exited — was ephemeral
        findings.append({
            "pid":      pid,
            "name":     name,
            "severity": "HIGH",
            "reason":   f"Process '{name}' (PID {pid}) visible in psutil but hidden from: {', '.join(missing_from)}",
        })

    # --- WMIC/tasklist have PID but psutil doesn't ---
    # Wait, then re-query BOTH psutil AND WMIC.
    # A genuinely hidden process will still appear in WMIC on the second pass.
    # A short-lived (ephemeral) process will have exited and disappear from WMIC too.
    external_only = (wmic_pids | tasklist_pids) - psutil_snap1
    if external_only:
        time.sleep(1.0)
        psutil_snap2 = _pids_from_psutil()
        wmic_snap2   = _pids_from_wmic()
        for pid in external_only:
            if pid in psutil_snap2:
                continue  # now visible in psutil — was briefly hidden or ephemeral
            if pid not in wmic_snap2:
                continue  # gone from WMIC too — was just a short-lived process
            # Still in WMIC but not in psutil on both checks — genuine suspect
            findings.append({
                "pid":      pid,
                "name":     "<unknown>",
                "severity": "HIGH",
                "reason":   f"PID {pid} persistently visible in WMIC but absent from psutil on multiple checks (possible kernel-level evasion)",
            })

    return findings


# ---------------------------------------------------------------------------
# Parent-child relationship check
# ---------------------------------------------------------------------------

# child_name -> set of acceptable parent names (lower-case).
# Based on normal Windows 10/11 process tree.
_EXPECTED_PARENTS: dict[str, set[str]] = {
    "services.exe":  {"wininit.exe"},
    "lsass.exe":     {"wininit.exe"},
    "svchost.exe":   {"services.exe"},
    "csrss.exe":     {"smss.exe"},
    "winlogon.exe":  {"smss.exe"},
    "wininit.exe":   {"smss.exe"},
    "explorer.exe":  {"userinit.exe", "winlogon.exe"},
    "spoolsv.exe":   {"services.exe"},
    "taskhost.exe":  {"services.exe"},
    # taskhostw.exe is legitimately started by svchost (Task Scheduler) on Win10/11
    "taskhostw.exe": {"services.exe", "svchost.exe"},
}


def check_parent_child() -> list[dict]:
    """Flag processes whose parent doesn't match the expected Windows tree."""
    pid_map = {p.info["pid"]: p for p in psutil.process_iter(["pid", "name", "ppid"])}
    findings = []
    for pid, proc in pid_map.items():
        try:
            child_name = proc.info["name"].lower()
            expected   = _EXPECTED_PARENTS.get(child_name)
            if expected is None:
                continue
            ppid   = proc.info["ppid"]
            parent = pid_map.get(ppid)
            if parent is None:
                continue
            parent_name = parent.info["name"].lower()
            if parent_name not in expected:
                findings.append({
                    "pid":      pid,
                    "name":     proc.info["name"],
                    "severity": "HIGH",
                    "reason": (
                        f"Suspicious parent: {proc.info['name']} (PID {pid}) is parented by "
                        f"{parent.info['name']} (PID {ppid}) — expected one of: {sorted(expected)}"
                    ),
                })
        except Exception:
            pass
    return findings


def run_analysis() -> list[dict]:
    return find_hidden_processes() + check_parent_child()
