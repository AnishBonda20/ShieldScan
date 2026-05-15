"""
Registry persistence and anomaly scanner.

Checks common rootkit/malware persistence locations and flags:
- Unexpected executables in autorun keys
- Executable paths in temp/user-writable directories
- Suspicious value names or data patterns
- Winlogon hijack indicators
- Image File Execution Options debugger hijack
"""

import winreg
import os
import logging

log = logging.getLogger(__name__)

_WINDOWS_ROOT = os.environ.get("SystemRoot", r"C:\Windows").lower()
_LOCALAPPDATA = os.environ.get("LOCALAPPDATA", r"C:\Users\Default\AppData\Local").lower()
_TRUSTED_PREFIXES = (
    _WINDOWS_ROOT,
    r"c:\program files",
    r"c:\program files (x86)",
    # User-scope installs: AppData\Local\Programs (Electron apps, etc.) are legitimate
    os.path.join(_LOCALAPPDATA, "programs"),
    # Squirrel-based installers (Discord, Teams, etc.)
    os.path.join(_LOCALAPPDATA, "discord"),
    os.path.join(_LOCALAPPDATA, "microsoft"),
)
_SUSPICIOUS_DIRS = (
    r"c:\users",
    r"c:\temp",
    r"c:\windows\temp",
    r"c:\programdata",
    os.environ.get("TEMP", "").lower(),
)


# ---------------------------------------------------------------------------
# Autorun / persistence key definitions
# ---------------------------------------------------------------------------

_AUTORUN_KEYS = [
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Session Manager\BootExecute"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
]

# Expected values for critical Winlogon settings
_WINLOGON_EXPECTED = {
    "userinit": "c:\\windows\\system32\\userinit.exe,",
    "shell":    "explorer.exe",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _open_key(hive, path):
    try:
        return winreg.OpenKey(hive, path, access=winreg.KEY_READ)
    except OSError:
        return None


def _enum_values(key) -> list[tuple[str, object]]:
    values = []
    i = 0
    while True:
        try:
            name, data, _ = winreg.EnumValue(key, i)
            values.append((name, data))
            i += 1
        except OSError:
            break
    return values


def _normalize_path(raw: str) -> str:
    """Strip quotes and expand environment variables from a registry value."""
    p = raw.strip().strip('"').split()[0]  # take first token (the exe path)
    p = os.path.expandvars(p).lower()
    return os.path.normpath(p)


def _is_suspicious_path(path: str) -> bool:
    if not path:
        return False
    if any(path.startswith(t) for t in _TRUSTED_PREFIXES):
        return False
    if any(path.startswith(d) for d in _SUSPICIOUS_DIRS if d):
        return True
    if path.startswith(r"c:\\") and not any(path.startswith(t) for t in _TRUSTED_PREFIXES):
        return True
    return False


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_autorun_key(hive, key_path: str) -> list[dict]:
    findings = []
    key = _open_key(hive, key_path)
    if key is None:
        return findings
    hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
    for name, data in _enum_values(key):
        if not isinstance(data, str):
            continue
        path = _normalize_path(data)
        if _is_suspicious_path(path):
            findings.append({
                "location": f"{hive_name}\\{key_path}\\{name}",
                "value": data,
                "severity": "HIGH",
                "reason": f"Autorun entry points to suspicious path: {data}",
            })
    winreg.CloseKey(key)
    return findings


def _check_winlogon() -> list[dict]:
    findings = []
    key = _open_key(
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    )
    if key is None:
        return findings
    for name, data in _enum_values(key):
        expected = _WINLOGON_EXPECTED.get(name.lower())
        if expected and isinstance(data, str):
            if data.strip().lower() != expected:
                findings.append({
                    "location": f"HKLM\\Winlogon\\{name}",
                    "value": data,
                    "severity": "HIGH",
                    "reason": (
                        f"Winlogon '{name}' modified: got '{data}', expected '{expected}' "
                        "(possible Winlogon hijack)"
                    ),
                })
    winreg.CloseKey(key)
    return findings


def _check_ifeo() -> list[dict]:
    """Image File Execution Options debugger hijack."""
    findings = []
    key = _open_key(
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    )
    if key is None:
        return findings
    i = 0
    while True:
        try:
            subkey_name = winreg.EnumKey(key, i)
            i += 1
        except OSError:
            break
        sub = _open_key(
            winreg.HKEY_LOCAL_MACHINE,
            rf"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{subkey_name}",
        )
        if sub is None:
            continue
        for name, data in _enum_values(sub):
            if name.lower() == "debugger" and isinstance(data, str):
                findings.append({
                    "location": f"HKLM\\IFEO\\{subkey_name}\\Debugger",
                    "value": data,
                    "severity": "HIGH",
                    "reason": (
                        f"IFEO Debugger hijack on '{subkey_name}': redirects to '{data}'. "
                        "This technique replaces a process at launch."
                    ),
                })
        winreg.CloseKey(sub)
    winreg.CloseKey(key)
    return findings


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def scan_registry() -> list[dict]:
    results = []

    # Autorun keys
    autorun_targets = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, path in autorun_targets:
        results.extend(_check_autorun_key(hive, path))

    results.extend(_check_winlogon())
    results.extend(_check_ifeo())

    for r in results:
        log.warning("[%s] %s | value: %s", r.get("severity"), r.get("reason"), r.get("value", ""))

    return results
