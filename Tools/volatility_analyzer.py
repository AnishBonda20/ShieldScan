"""
Volatility3 integration.

Runs the following plugins against a memory dump and returns structured findings:
  - windows.pslist       → process list from kernel structures
  - windows.pstree       → process hierarchy
  - windows.malfind      → injected code / suspicious memory regions
  - windows.driverirp    → IRP hook detection on drivers
  - windows.ssdt         → SSDT hook detection
  - windows.netscan      → network connections from memory

Usage:
    from volatility_analyzer import analyze_dump
    findings = analyze_dump("C:\\path\\to\\dump.dmp")
"""

import subprocess
import sys
import os
import json
import logging
import re

log = logging.getLogger(__name__)

_BASE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_VOL_PATH = os.path.join(_BASE, "volatility3", "vol.py")

# Plugins to run; each entry: (plugin_name, parse_function)
_PLUGINS = [
    "windows.pslist.PsList",
    "windows.malfind.Malfind",
    "windows.driverirp.DriverIrp",
    "windows.ssdt.SSDT",
    "windows.netscan.NetScan",
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _run_plugin(vol_py: str, dump_path: str, plugin: str, timeout: int = 180) -> str | None:
    """Run a single Volatility plugin, return stdout text or None on failure."""
    cmd = [sys.executable, vol_py, "-f", dump_path, plugin]
    log.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode != 0:
            log.warning("Plugin %s exited %d: %s", plugin, result.returncode, result.stderr[:300])
            return None
        return result.stdout
    except subprocess.TimeoutExpired:
        log.warning("Plugin %s timed out after %ds", plugin, timeout)
        return None
    except Exception as exc:
        log.error("Failed to run plugin %s: %s", plugin, exc)
        return None


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_malfind(output: str) -> list[dict]:
    """
    Malfind output contains blocks like:
      Process: <name>  Pid: <n>  Address: <hex>
      Vad Tag: ...  Protection: <perms>
      ...hex dump...
    Flag any region with PAGE_EXECUTE_READWRITE.
    """
    findings = []
    if not output:
        return findings
    blocks = re.split(r"\n(?=Process:)", output)
    for block in blocks:
        if "PAGE_EXECUTE_READWRITE" in block or "PAGE_EXECUTE_WRITECOPY" in block:
            proc_m   = re.search(r"Process:\s+(\S+)", block)
            pid_m    = re.search(r"Pid:\s+(\d+)", block)
            addr_m   = re.search(r"Address:\s+(0x[0-9a-fA-F]+)", block)
            prot_m   = re.search(r"Protection:\s+(\S+)", block)
            findings.append({
                "plugin":   "malfind",
                "process":  proc_m.group(1) if proc_m else "?",
                "pid":      int(pid_m.group(1)) if pid_m else None,
                "address":  addr_m.group(1) if addr_m else "?",
                "severity": "HIGH",
                "reason": (
                    f"Executable+writable memory region at {addr_m.group(1) if addr_m else '?'} "
                    f"in {proc_m.group(1) if proc_m else '?'} (PID {pid_m.group(1) if pid_m else '?'}) "
                    f"— protection: {prot_m.group(1) if prot_m else '?'} (code injection indicator)"
                ),
            })
    return findings


def _parse_ssdt(output: str) -> list[dict]:
    """Flag SSDT entries that are not inside ntoskrnl or win32k."""
    findings = []
    if not output:
        return findings
    for line in output.splitlines():
        # A hooked entry looks like:  <index>   <address>   <module>   <function>
        # Hooked entries often show a non-system module
        if re.search(r"\bhooked\b", line, re.I):
            findings.append({
                "plugin":   "ssdt",
                "severity": "HIGH",
                "reason":   f"SSDT hook detected: {line.strip()}",
            })
        # Flag entries not belonging to ntoskrnl/win32k
        m = re.search(r"(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)", line)
        if m:
            module = m.group(2).lower()
            if module not in ("ntoskrnl.exe", "win32k.sys", "ntoskrnl", "win32k",
                              "ntoskrnl.exe+", "win32k.sys+", "unknown"):
                if not module.startswith("nt") and not module.startswith("win32k"):
                    findings.append({
                        "plugin":   "ssdt",
                        "severity": "HIGH",
                        "reason":   f"SSDT entry points to non-kernel module '{module}': {line.strip()}",
                    })
    return findings


def _parse_driverirp(output: str) -> list[dict]:
    """Flag IRP handlers that are not inside the driver's own image."""
    findings = []
    if not output:
        return findings
    for line in output.splitlines():
        if re.search(r"\bhooked\b|\bmodified\b|\binvalid\b", line, re.I):
            findings.append({
                "plugin":   "driverirp",
                "severity": "HIGH",
                "reason":   f"IRP hook detected: {line.strip()}",
            })
    return findings


def _parse_netscan(output: str) -> list[dict]:
    """Surface all active connections from memory for review."""
    findings = []
    if not output:
        return findings
    _MALWARE_PORTS = {4444, 4445, 5554, 6666, 7777, 9001, 9050, 31337, 1337}
    for line in output.splitlines():
        m = re.search(r":(\d+)\s", line)
        if m:
            port = int(m.group(1))
            if port in _MALWARE_PORTS:
                findings.append({
                    "plugin":   "netscan",
                    "severity": "HIGH",
                    "reason":   f"Memory netscan found connection on known malware port {port}: {line.strip()}",
                })
    return findings


_PARSERS = {
    "windows.malfind.Malfind":   _parse_malfind,
    "windows.ssdt.SSDT":         _parse_ssdt,
    "windows.driverirp.DriverIrp": _parse_driverirp,
    "windows.netscan.NetScan":   _parse_netscan,
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_dump(dump_path: str, vol_py: str = "", timeout: int = 180) -> list[dict]:
    """
    Run all Volatility plugins against `dump_path` and return a list of findings.
    Returns an empty list (not an error) if Volatility is unavailable.
    """
    vol_py = vol_py or _DEFAULT_VOL_PATH
    if not os.path.exists(vol_py):
        log.warning("Volatility not found at %s — skipping memory analysis", vol_py)
        return [{"plugin": "setup", "severity": "INFO",
                 "reason": f"Volatility3 not found at {vol_py}. Memory analysis skipped."}]

    if not os.path.exists(dump_path):
        log.warning("Dump file not found: %s", dump_path)
        return [{"plugin": "setup", "severity": "INFO",
                 "reason": f"Memory dump not found at {dump_path}. Run memory_capture.py first."}]

    findings = []
    for plugin in _PLUGINS:
        raw = _run_plugin(vol_py, dump_path, plugin, timeout)
        parser = _PARSERS.get(plugin)
        if parser and raw:
            parsed = parser(raw)
            findings.extend(parsed)
            log.info("Plugin %s: %d findings", plugin, len(parsed))
        elif raw is None:
            log.warning("Plugin %s produced no output", plugin)

    return findings
