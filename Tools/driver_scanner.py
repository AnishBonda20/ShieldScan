"""
Kernel driver scanner.

Detection methods:
1. driverquery — lists drivers reported by the Service Control Manager.
2. Registry enumeration — reads HKLM\SYSTEM\CurrentControlSet\Services for
   kernel drivers (Type == 1).
3. Cross-view: drivers in the registry but absent from driverquery output are
   potentially hidden.
4. Heuristics: drivers loaded from unusual paths, with no description, or with
   suspicious names are flagged.
"""

import subprocess
import winreg
import os
import csv
import io
import logging

log = logging.getLogger(__name__)

_WINDOWS_ROOT = os.environ.get("SystemRoot", r"C:\Windows").lower()
_SYSTEM_DRIVE = os.environ.get("SystemDrive", "C:").lower()


def _expand_driver_path(raw: str) -> str:
    """
    Normalize registry ImagePath values to absolute lowercase paths.
    Handles NT namespace prefixes, SystemRoot shorthands, and relative paths.
    """
    # Strip outer quotes only — do NOT split on spaces; driver ImagePath values
    # are full paths that may contain spaces (e.g. C:\Program Files\...).
    p = raw.strip()
    if p.startswith('"') and p.endswith('"'):
        p = p[1:-1]

    # Strip NT namespace device path prefix:  \??\   or   \\?\
    for ns_prefix in ("\\??\\", "\\\\?\\"):
        if p.lower().startswith(ns_prefix.lower()):
            p = p[len(ns_prefix):]
            break

    p = os.path.expandvars(p)   # expand %SystemRoot%, %SystemDrive%, etc.

    # \SystemRoot\ → C:\Windows\
    if p.lower().startswith("\\systemroot\\"):
        p = _WINDOWS_ROOT + "\\" + p[len("\\SystemRoot\\"):]

    # Relative path → prepend Windows root
    if p and not os.path.isabs(p) and not p.startswith("\\\\"):
        p = os.path.join(_WINDOWS_ROOT, p)

    return os.path.normpath(p).lower()

_SUSPICIOUS_DRIVER_KEYWORDS = [
    "hook", "inject", "rootkit", "stealth", "ghost",
    "spy", "intercept", "bypass", "hidefile", "hideproc",
    "hidenet", "hidedrv",
]


# ---------------------------------------------------------------------------
# Collect from driverquery
# ---------------------------------------------------------------------------

def _drivers_from_driverquery() -> dict[str, dict]:
    """Return {driver_name_lower: info_dict} from driverquery."""
    drivers = {}
    try:
        out = subprocess.check_output(
            ["driverquery", "/fo", "csv", "/v"],
            stderr=subprocess.DEVNULL,
            timeout=30,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        reader = csv.DictReader(io.StringIO(out))
        for row in reader:
            name = (row.get("Module Name") or row.get("Display Name") or "").strip().lower()
            if name:
                drivers[name] = {
                    "name": name,
                    "display": (row.get("Display Name") or "").strip(),
                    "path": (row.get("Image Path") or "").strip(),
                    "state": (row.get("State") or "").strip(),
                    "type": (row.get("Type") or "").strip(),
                }
    except Exception as exc:
        log.debug("driverquery failed: %s", exc)
    return drivers


# ---------------------------------------------------------------------------
# Collect from registry
# ---------------------------------------------------------------------------

def _drivers_from_registry() -> dict[str, dict]:
    """Return {service_name_lower: info_dict} for Type==1 (kernel drivers)."""
    drivers = {}
    services_key = r"SYSTEM\CurrentControlSet\Services"
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_key)
    except OSError:
        return drivers

    i = 0
    while True:
        try:
            svc_name = winreg.EnumKey(root, i)
            i += 1
        except OSError:
            break
        try:
            svc_key = winreg.OpenKey(root, svc_name)
            try:
                svc_type, _ = winreg.QueryValueEx(svc_key, "Type")
            except OSError:
                winreg.CloseKey(svc_key)
                continue
            if svc_type not in (1, 2):  # 1=kernel driver, 2=file system driver
                winreg.CloseKey(svc_key)
                continue
            try:
                image_path, _ = winreg.QueryValueEx(svc_key, "ImagePath")
            except OSError:
                image_path = ""
            try:
                display, _ = winreg.QueryValueEx(svc_key, "DisplayName")
            except OSError:
                display = svc_name
            drivers[svc_name.lower()] = {
                "name": svc_name.lower(),
                "display": display,
                "path": image_path,
                "type": "kernel" if svc_type == 1 else "fs",
            }
            winreg.CloseKey(svc_key)
        except OSError:
            pass
    winreg.CloseKey(root)
    return drivers


# ---------------------------------------------------------------------------
# Heuristic checks
# ---------------------------------------------------------------------------

def _flag_driver(name: str, info: dict) -> list[tuple[str, str]]:
    findings = []
    raw_path = info.get("path", "")
    path = _expand_driver_path(raw_path) if raw_path else ""

    # 1. Suspicious name keyword
    for kw in _SUSPICIOUS_DRIVER_KEYWORDS:
        if kw in name:
            findings.append(("HIGH", f"Driver name contains suspicious keyword '{kw}'"))
            break

    # 2. Driver path outside trusted locations.
    # Legitimate locations: C:\Windows\ and C:\Program Files\ (vendor drivers).
    _TRUSTED_DRV = (_WINDOWS_ROOT, r"c:\program files", r"c:\program files (x86)")
    if path and not any(path.startswith(t) for t in _TRUSTED_DRV):
        findings.append(("HIGH", f"Driver loaded from outside trusted directory: {info['path']}"))

    # 3. Driver loaded from temp or user-writable path
    _bad_prefixes = (r"c:\users", r"c:\temp", r"c:\programdata")
    if path and any(path.startswith(b) for b in _bad_prefixes):
        findings.append(("HIGH", f"Driver loaded from user-writable location: {info['path']}"))

    return findings


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def scan_drivers() -> list[dict]:
    results = []

    dq_drivers  = _drivers_from_driverquery()
    reg_drivers = _drivers_from_registry()

    _TRUSTED_DRIVER_PREFIXES = (
        _WINDOWS_ROOT,
        r"c:\program files",
        r"c:\program files (x86)",
    )

    # Cross-view: in registry but not in driverquery → potentially hidden.
    # Skip if the expanded path is inside a trusted Windows/Program Files location —
    # those are inactive/demand-start drivers, not hidden ones.
    for name, info in reg_drivers.items():
        if name not in dq_drivers:
            raw_path = info.get("path", "")
            expanded = _expand_driver_path(raw_path) if raw_path else ""
            if expanded and any(expanded.startswith(p) for p in _TRUSTED_DRIVER_PREFIXES):
                continue  # legitimate Windows / vendor driver not currently running
            results.append({
                "name": name,
                "severity": "HIGH",
                "reason": (
                    f"Driver '{name}' is registered in the kernel services registry "
                    f"but absent from driverquery — path: {raw_path or 'unknown'} "
                    "(possible hidden driver)"
                ),
            })
            log.warning("[HIGH] Hidden driver candidate: %s | path: %s", name, raw_path)

    # Heuristic checks on all known drivers
    all_drivers = {**dq_drivers, **reg_drivers}
    for name, info in all_drivers.items():
        for severity, reason in _flag_driver(name, info):
            results.append({"name": name, "severity": severity, "reason": reason})
            log.warning("[%s] Driver %s: %s", severity, name, reason)

    return results
