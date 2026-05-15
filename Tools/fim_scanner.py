"""
File Integrity Monitor (FIM).

Hashes a fixed list of critical Windows system files and compares against
stored known-good values.  Flags any file that has been modified, replaced,
or deleted since the FIM baseline was established.

Baseline:
  Stored at logs/fim_hashes.json.
  Created automatically on the first run.
  To reset: delete logs/fim_hashes.json  (next run will re-baseline).
  To update intentionally (e.g. after a legitimate Windows update):
      python main.py --reset-fim
"""

from __future__ import annotations

import os
import json
import hashlib
import logging
from datetime import datetime

log = logging.getLogger(__name__)

_HERE      = os.path.dirname(os.path.abspath(__file__))
_HASH_FILE = os.path.join(_HERE, "logs", "fim_hashes.json")

# -----------------------------------------------------------------------
# Files to monitor
# -----------------------------------------------------------------------
_CRITICAL_FILES: list[str] = [
    # Kernel / HAL
    r"C:\Windows\System32\ntoskrnl.exe",
    r"C:\Windows\System32\ntkrnlpa.exe",
    r"C:\Windows\System32\hal.dll",
    # Core user-mode DLLs (frequent rootkit patching targets)
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\kernelbase.dll",
    r"C:\Windows\System32\advapi32.dll",
    r"C:\Windows\System32\user32.dll",
    r"C:\Windows\System32\ws2_32.dll",
    r"C:\Windows\System32\msvcrt.dll",
    r"C:\Windows\System32\sechost.dll",
    r"C:\Windows\System32\rpcrt4.dll",
    # Security / auth
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\lsasrv.dll",
    r"C:\Windows\System32\samsrv.dll",
    # Boot-critical processes
    r"C:\Windows\System32\services.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\winlogon.exe",
    r"C:\Windows\System32\wininit.exe",
    r"C:\Windows\System32\csrss.exe",
    r"C:\Windows\System32\smss.exe",
    r"C:\Windows\System32\userinit.exe",
    # Shell / management
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\taskmgr.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\System32\wbem\wmic.exe",
    # Critical kernel drivers
    r"C:\Windows\System32\drivers\tcpip.sys",
    r"C:\Windows\System32\drivers\ndis.sys",
    r"C:\Windows\System32\drivers\http.sys",
    r"C:\Windows\System32\drivers\ntfs.sys",
    r"C:\Windows\System32\drivers\fastfat.sys",
    r"C:\Windows\System32\drivers\storport.sys",
    r"C:\Windows\System32\drivers\pci.sys",
]


# -----------------------------------------------------------------------
# Hashing
# -----------------------------------------------------------------------

def _sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(131072), b""):
                h.update(chunk)
        return h.hexdigest()
    except PermissionError:
        return "ACCESS_DENIED"
    except FileNotFoundError:
        return "MISSING"
    except OSError as exc:
        log.debug("Hash error for %s: %s", path, exc)
        return "ERROR"


def _hash_all(paths: list[str]) -> dict[str, str]:
    return {p: _sha256(p) for p in paths}


# -----------------------------------------------------------------------
# Baseline persistence
# -----------------------------------------------------------------------

def _load_baseline() -> dict[str, str]:
    if not os.path.exists(_HASH_FILE):
        return {}
    try:
        with open(_HASH_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("hashes", {})
    except Exception as exc:
        log.warning("FIM: could not read baseline %s: %s", _HASH_FILE, exc)
        return {}


def _save_baseline(hashes: dict[str, str]) -> None:
    os.makedirs(os.path.dirname(_HASH_FILE), exist_ok=True)
    with open(_HASH_FILE, "w", encoding="utf-8") as f:
        json.dump({"saved_at": datetime.now().isoformat(), "hashes": hashes}, f, indent=2)
    log.info("FIM: baseline saved to %s (%d files)", _HASH_FILE, len(hashes))


def reset_baseline() -> None:
    """Delete the stored FIM baseline so it is re-established on the next scan."""
    if os.path.exists(_HASH_FILE):
        os.remove(_HASH_FILE)
        log.info("FIM: baseline reset — will re-establish on next scan")


# -----------------------------------------------------------------------
# Main scan
# -----------------------------------------------------------------------

_SKIP = {"ACCESS_DENIED", "ERROR"}   # hashes we cannot compare reliably


def scan_file_integrity() -> list[dict]:
    """
    Hash all monitored files and compare against the stored baseline.

    First run  → establishes the baseline; reports missing files only.
    Later runs → flags modifications and deletions.
    Returns a list of finding dicts.
    """
    stored  = _load_baseline()
    current = _hash_all(_CRITICAL_FILES)
    findings: list[dict] = []

    if not stored:
        # First-run baseline establishment
        _save_baseline(current)
        log.info("FIM: baseline established for %d files", len(current))
        # Still flag missing files immediately
        for path, h in current.items():
            if h == "MISSING":
                findings.append({
                    "severity": "HIGH",
                    "reason":   f"FIM: critical system file missing on first scan: {path}",
                    "name":     os.path.basename(path),
                    "location": path,
                })
        return findings

    for path, h in current.items():
        fname   = os.path.basename(path)
        stored_h = stored.get(path)

        if stored_h is None:
            # New file added since baseline — informational only
            continue

        if h == "MISSING" and stored_h not in _SKIP and stored_h != "MISSING":
            findings.append({
                "severity": "HIGH",
                "reason":   f"FIM: critical file DELETED since baseline: {path}",
                "name":     fname,
                "location": path,
            })
        elif h not in _SKIP and stored_h not in _SKIP and h != stored_h:
            findings.append({
                "severity": "HIGH",
                "reason":   (
                    f"FIM: critical file MODIFIED since baseline: {path} "
                    f"(hash {stored_h[:12]}… → {h[:12]}…)"
                ),
                "name":     fname,
                "location": path,
            })

    if findings:
        log.warning("FIM: %d integrity violation(s) detected", len(findings))
    else:
        log.info("FIM: all %d monitored files intact", len(current))

    return findings
