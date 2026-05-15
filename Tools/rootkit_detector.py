import psutil
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Processes that must live in specific directories; anything else is masquerading.
_SYSTEM_PROCESS_PATHS = {
    "svchost.exe":   r"c:\windows\system32\svchost.exe",
    "lsass.exe":     r"c:\windows\system32\lsass.exe",
    "csrss.exe":     r"c:\windows\system32\csrss.exe",
    "winlogon.exe":  r"c:\windows\system32\winlogon.exe",
    "services.exe":  r"c:\windows\system32\services.exe",
    "smss.exe":      r"c:\windows\system32\smss.exe",
    "wininit.exe":   r"c:\windows\system32\wininit.exe",
    "spoolsv.exe":   r"c:\windows\system32\spoolsv.exe",
    "explorer.exe":  r"c:\windows\explorer.exe",
    "taskhost.exe":  r"c:\windows\system32\taskhost.exe",
    "taskhostw.exe": r"c:\windows\system32\taskhostw.exe",
    "dwm.exe":       r"c:\windows\system32\dwm.exe",
}

_SYSTEM_PIDS = {0, 4}

_BAD_KEYWORDS = frozenset(
    ["rootkit", "malware", "hidden", "backdoor", "keylog", "inject", "hook"]
)

# Computed once at import time — not inside the per-process loop.
_LOCALAPPDATA = os.environ.get("LOCALAPPDATA", "").lower()
_APPDATA      = os.environ.get("APPDATA", "").lower()
_TEMP_DIRS = tuple(filter(None, {
    r"c:\temp",
    r"c:\windows\temp",
    os.path.join(_LOCALAPPDATA, "temp") if _LOCALAPPDATA else "",
    os.path.join(_APPDATA, "temp")      if _APPDATA else "",
    os.environ.get("TEMP", "").lower(),
    os.environ.get("TMP", "").lower(),
}))

log = logging.getLogger(__name__)


def _normalize(path: str) -> str:
    return os.path.normpath(path).lower()


def check_process(proc) -> list[tuple[str, str]]:
    """Return list of (severity, reason) for a single process. Empty = clean."""
    findings = []
    try:
        name = proc.name().lower()
        try:
            exe = _normalize(proc.exe())
        except (psutil.AccessDenied, OSError):
            exe = ""
        ppid = proc.ppid()

        # 1. Masquerade: known system process name running from wrong path.
        expected = _SYSTEM_PROCESS_PATHS.get(name)
        if expected and exe and exe != expected:
            findings.append((
                "HIGH",
                f"Masquerading as {name} — runs from {exe} (expected {expected})",
            ))

        # 2. Orphan: process with no parent that isn't a Windows kernel process.
        if ppid == 0 and proc.pid not in _SYSTEM_PIDS:
            findings.append(("MEDIUM", "No parent process (possible evasion)"))

        # 3. Suspicious name keyword.
        if any(kw in name for kw in _BAD_KEYWORDS):
            findings.append(("HIGH", "Process name contains suspicious keyword"))

        # 4. Executable running from a temp directory (never legitimate).
        if exe and any(exe.startswith(d) for d in _TEMP_DIRS if d):
            findings.append(("HIGH", f"Executable running from temp directory: {exe}"))

        # 5. DLL loaded from a temp directory — strong code-injection indicator.
        try:
            for m in proc.memory_maps()[:40]:
                p = _normalize(m.path)
                if p.endswith(".dll") and any(p.startswith(d) for d in _TEMP_DIRS if d):
                    findings.append(("HIGH", f"DLL injected from temp directory: {m.path}"))
                    break
        except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
            pass

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    return findings


def scan_processes(logger=None) -> list[dict]:
    """
    Scan all running processes in parallel.
    Returns list of finding dicts.
    """
    lg = logger or log
    procs  = list(psutil.process_iter(["pid", "name"]))
    results = []

    with ThreadPoolExecutor(max_workers=min(32, len(procs))) as pool:
        future_to_proc = {pool.submit(check_process, p): p for p in procs}
        for future in as_completed(future_to_proc):
            proc = future_to_proc[future]
            try:
                findings = future.result()
            except Exception as exc:
                lg.debug("Error inspecting PID %s: %s", getattr(proc, "pid", "?"), exc)
                continue
            for severity, reason in findings:
                entry = {
                    "pid":      proc.pid,
                    "name":     proc.name(),
                    "severity": severity,
                    "reason":   reason,
                }
                results.append(entry)
                lg.warning("[%s] PID %d (%s): %s", severity, proc.pid, proc.name(), reason)

    return results
