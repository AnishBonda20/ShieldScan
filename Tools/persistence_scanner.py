"""
Persistence mechanism scanner  —  with double-check verification.

Every suspicious finding goes through a second-opinion step:
  • Authenticode signature check  (trusted publisher → skip or downgrade)
  • Service type filter            (kernel/FS drivers are not user-mode threats)
  • LSA package path verification  (DLL must exist inside System32)

Checks:
  1. Scheduled tasks  — suspicious paths / raw scripts
  2. WMI subscriptions — fileless EventFilter/Consumer pairs
  3. Startup folders   — executables dropped directly (not .lnk shortcuts)
  4. BootExecute key   — non-standard pre-boot entries
  5. Services          — ImagePath in temp / user-writable dirs (user-mode only)
  6. AppInit_DLLs / LSA packages  — registry DLL injection vectors
"""

from __future__ import annotations

import functools
import json
import logging
import os
import re
import subprocess
import winreg

log = logging.getLogger(__name__)

# RAG filter — optional; gracefully degrades if unavailable
try:
    from rag_filter import rag_filter as _rag
    _RAG_AVAILABLE = True
except Exception:
    _rag = None
    _RAG_AVAILABLE = False

# -----------------------------------------------------------------------
# Shared path helpers
# -----------------------------------------------------------------------

# Paths that are genuinely suspicious for executables registered as tasks/services.
# NOTE: "\\appdata\\roaming\\" is intentionally excluded — many legitimate
#       Electron apps (Discord, Slack …) install there legitimately.
_SUSPICIOUS_DIRS = (
    "\\appdata\\local\\temp\\",
    "\\temp\\",
    "\\tmp\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\desktop\\",
    "$recycle.bin",
    "\\recycle\\",
)

# Task names that start with any of these prefixes are always trusted.
_TRUSTED_TASK_PREFIXES = (
    "\\microsoft\\windows\\",
    "\\microsoft\\windowsdefender",
    "\\microsoft\\office\\",
    "\\microsoft\\onedrive",
    "\\microsoftedge",
    "\\adobegenuineclient",
    "\\googleupdate",
    "\\mozillacorporation",
    "\\zoom",
    "\\zoomupdatetask",
    "\\teamviewer",
    "\\anydesk",
    "\\ccleaner",
    "\\nvidia",
    "\\intel",
    "\\dropbox",
    "\\spotify",
    "\\steam",
    "\\epicgameslauncher",
    "\\discord",
    "\\slack",
    "\\ollama",
    "\\hp\\",
    "\\hewlett",
    "\\systemoptimizer",
    "\\dell",
    "\\lenovo",
    "\\acer",
    "\\samsung",
    "\\realtek",
    "\\user_feed_synchronization",
)

# Publishers whose Authenticode signature tells us an exe is legitimate.
_TRUSTED_PUBLISHERS: frozenset[str] = frozenset({
    "microsoft corporation",
    "microsoft windows",
    "microsoft time-stamp service",
    "google llc",
    "zoom video communications",
    "mozilla corporation",
    "apple inc.",
    "adobe inc.",
    "oracle america",
    "intel corporation",
    "nvidia corporation",
    "advanced micro devices",
    "logitech inc",
    "razer inc",
    "spotify ab",
    "slack technologies",
    "dropbox, inc",
    "discord inc.",
    "valve corporation",
    "epic games",
    "anydesk software gmbh",
    "teamviewer germany gmbh",
    "piriform software",
    "iobit information technology",
    "malwarebytes inc",
    "avast software",
    "avg technologies",
    "kaspersky lab",
    "bitdefender srl",
    "gen digital inc",
    "nordvpn s.a.",
    "expressvpn",
    # HP / Hewlett-Packard
    "hp inc.",
    "hewlett-packard company",
    "hewlett packard enterprise",
    # OEM / system vendors
    "dell inc",
    "lenovo",
    "acer incorporated",
    "asus",
    "samsung electronics",
    "realtek semiconductor",
    "qualcomm",
    "broadcom",
    # Common utilities
    "ollama, inc",
    "onenote",
    "7-zip",
    "winrar gmbh",
    "python software foundation",
})


def _is_suspicious_path(path: str) -> bool:
    p = path.lower()
    return any(d in p for d in _SUSPICIOUS_DIRS)


def _is_trusted_task(name: str) -> bool:
    # Strip leading slash from both sides before comparing so that
    # "\ZoomUpdateTaskUser-…" correctly matches prefix "\zoomupdatetask"
    n = name.lower().replace("\\", "/").lstrip("/")
    return any(n.startswith(p.replace("\\", "/").lstrip("/"))
               for p in _TRUSTED_TASK_PREFIXES)


# -----------------------------------------------------------------------
# Authenticode double-check  (cached — PowerShell is expensive to spawn)
# -----------------------------------------------------------------------

@functools.lru_cache(maxsize=256)
def _is_trusted_signature(raw_path: str) -> bool:
    """
    Return True if the executable at *raw_path* carries a valid Authenticode
    signature from a known-trusted publisher.  Results are cached per path.
    """
    path = os.path.expandvars(raw_path.strip('"').strip("'").strip())
    if not path or not os.path.isfile(path):
        return False
    try:
        # Escape single-quotes in the path so PowerShell doesn't choke
        safe = path.replace("'", "''")
        ps = (
            f"$s = Get-AuthenticodeSignature -LiteralPath '{safe}' -EA SilentlyContinue;"
            "if ($s -and $s.Status -eq 'Valid') { $s.SignerCertificate.Subject } else { '' }"
        )
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            stderr=subprocess.DEVNULL, timeout=10, text=True,
        ).strip().lower()
        return bool(out) and any(pub in out for pub in _TRUSTED_PUBLISHERS)
    except Exception:
        return False


def _extract_exe(action: str) -> str:
    """Pull the executable path out of a task-action string."""
    action = action.strip()
    # Quoted: "C:\path\app.exe" [args...]
    m = re.match(r'"([^"]+)"', action)
    if m:
        return m.group(1)
    # Unquoted: C:\path\app.exe [args...]
    parts = action.split()
    return parts[0] if parts else ""


# -----------------------------------------------------------------------
# 1. Scheduled tasks
# -----------------------------------------------------------------------

def _scan_scheduled_tasks() -> list[dict]:
    """
    Flag tasks whose executable is in a suspicious location or runs a raw script.
    Each candidate is given a second check:
      - If the exe is signed by a trusted publisher  → silent skip
      - Scripts from trusted system dirs             → skip
    """
    findings: list[dict] = []
    try:
        out = subprocess.check_output(
            ["schtasks", "/query", "/fo", "LIST", "/v"],
            stderr=subprocess.DEVNULL, timeout=60, text=True, errors="replace",
        )
    except Exception as exc:
        log.debug("schtasks query failed: %s", exc)
        return findings

    task_name = task_action = task_user = ""

    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("TaskName:"):
            if task_name and task_action:
                _check_task(task_name, task_action, task_user, findings)
            task_name   = line.split(":", 1)[1].strip()
            task_action = task_user = ""
        elif line.startswith("Task To Run:"):
            task_action = line.split(":", 1)[1].strip()
        elif line.startswith("Run As User:"):
            task_user = line.split(":", 1)[1].strip()

    if task_name and task_action:
        _check_task(task_name, task_action, task_user, findings)

    return findings


def _check_task(name: str, action: str, user: str, findings: list[dict]) -> None:
    if _is_trusted_task(name):
        return
    if action.upper() in ("N/A", "COM HANDLER", ""):
        return

    action_l = action.lower()
    exe_path  = _extract_exe(action)

    # ── Suspicious path check ──────────────────────────────────
    if _is_suspicious_path(action_l):
        # Double-check: trusted signature overrides a suspicious path
        if _is_trusted_signature(exe_path):
            log.debug("Task '%s': suspicious path but trusted signature — skipped", name)
            return
        findings.append({
            "severity": "HIGH",
            "reason":   (f"Scheduled task '{name}' runs from suspicious path: {action}"
                         f" — not signed by a trusted publisher"),
            "name":     name,
            "location": action,
        })
        return

    # ── Script execution check ────────────────────────────────
    if re.search(r"\.(ps1|vbs|js|jse|bat|cmd|hta|wsf)\b", action_l):
        # Scripts inside Windows / Program Files are typically fine
        safe_script_roots = (
            "\\windows\\", "\\program files\\", "\\program files (x86)\\",
        )
        if any(s in action_l for s in safe_script_roots):
            return
        # Double-check: if the script lives somewhere else, still flag it
        findings.append({
            "severity": "MEDIUM",
            "reason":   (f"Scheduled task '{name}' runs a script: {action}"
                         f" — verify this is intentional"),
            "name":     name,
            "location": action,
        })
        return

    # ── SYSTEM task using shell interpreter ───────────────────
    if (user.upper() in ("SYSTEM", "NT AUTHORITY\\SYSTEM")
            and re.search(r"\bpowershell\b|\bcmd\.exe\b|\bwscript\b|\bcscript\b", action_l)):
        if _is_trusted_signature(exe_path):
            return
        findings.append({
            "severity": "MEDIUM",
            "reason":   (f"SYSTEM-run task uses shell interpreter: '{name}' → {action}"
                         f" — confirm this is a legitimate maintenance task"),
            "name":     name,
            "location": action,
        })


# -----------------------------------------------------------------------
# 2. WMI event subscriptions
# -----------------------------------------------------------------------

_SAFE_WMI_NAMES: set[str] = {
    "scm event log filter",
    "scm event log consumer",
    "consumer:scm event log consumer",
    "bvtfilter",
    "nteventsystemfilter",
    "nteventsystemconsumer",
    "consumer:nteventsystemconsumer",
    # Windows built-in subscriptions seen on stock installs
    "msft_storageeventfilter",
    "iedllfilter",
    "wmi activity",
}


def _scan_wmi_subscriptions() -> list[dict]:
    """
    Detect permanent WMI event subscriptions.
    Windows-built-in subscriptions are whitelisted; anything else is flagged.
    For consumer entries the command-line is also signature-checked.
    """
    findings: list[dict] = []
    ps_cmd = (
        "try {"
        "  $f = Get-WMIObject -Namespace 'root\\subscription' -Class __EventFilter -EA Stop;"
        "  $c = Get-WMIObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -EA SilentlyContinue;"
        "  $r = @();"
        "  foreach ($x in $f) { $r += [PSCustomObject]@{ Name=$x.Name; Query=$x.Query; Cmd='' } };"
        "  foreach ($x in $c) { $r += [PSCustomObject]@{ Name='CONSUMER:'+$x.Name; Query=''; Cmd=$x.CommandLineTemplate } };"
        "  $r | ConvertTo-Json -Compress"
        "} catch { '[]' }"
    )
    try:
        raw = subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            stderr=subprocess.DEVNULL, timeout=30, text=True,
        ).strip()

        if not raw or raw in ("null", "[]", ""):
            return findings

        items = json.loads(raw)
        if isinstance(items, dict):
            items = [items]

        for item in items:
            entry_name = item.get("Name", "<unknown>")
            if entry_name.lower() in _SAFE_WMI_NAMES:
                continue

            cmd   = (item.get("Cmd") or "").strip()
            query = (item.get("Query") or "")[:200]

            # Double-check: if the consumer command points to a trusted exe, lower severity
            if cmd:
                exe = _extract_exe(cmd)
                if _is_trusted_signature(exe):
                    log.debug("WMI '%s': trusted signature on consumer cmd — skipped", entry_name)
                    continue

            detail = f"Command: {cmd}" if cmd else f"Query: {query}"
            findings.append({
                "severity": "HIGH",
                "reason":   (f"WMI event subscription: '{entry_name}' — "
                             f"fileless persistence technique. {detail}"),
                "name": entry_name,
            })
    except Exception as exc:
        log.debug("WMI subscription scan failed: %s", exc)

    return findings


# -----------------------------------------------------------------------
# 3. Startup folders
# -----------------------------------------------------------------------

# .lnk shortcuts are the NORMAL mechanism for startup entries — never flag them.
# Only flag executables / scripts dropped directly into the folder.
_STARTUP_EXTS = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".hta", ".wsf"}


def _scan_startup_folders() -> list[dict]:
    """
    Check user and all-users startup folders for unexpected executables.
    Files signed by a trusted publisher are skipped (double-check).
    """
    findings: list[dict] = []
    folders: list[str] = []

    appdata = os.environ.get("APPDATA", "")
    if appdata:
        folders.append(
            os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup")
        )
    folders.append(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")

    for folder in folders:
        if not os.path.isdir(folder):
            continue
        try:
            for entry in os.scandir(folder):
                if entry.name.lower() == "desktop.ini":
                    continue
                ext = os.path.splitext(entry.name)[1].lower()
                if ext not in _STARTUP_EXTS:
                    continue
                # Double-check: trusted signature → skip
                if _is_trusted_signature(entry.path):
                    log.debug("Startup '%s': trusted signature — skipped", entry.name)
                    continue
                findings.append({
                    "severity": "HIGH",
                    "reason":   (f"Unsigned executable in startup folder: "
                                 f"'{entry.name}' in {folder}"),
                    "name":     entry.name,
                    "location": entry.path,
                })
        except PermissionError:
            pass

    return findings


# -----------------------------------------------------------------------
# 4. BootExecute registry key
# -----------------------------------------------------------------------

_NORMAL_BOOT_EXECUTE: set[str] = {"autocheck autochk *", ""}


def _scan_boot_execute() -> list[dict]:
    """Flag non-standard BootExecute entries (pre-boot persistence)."""
    findings: list[dict] = []
    key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
            try:
                val, _ = winreg.QueryValueEx(k, "BootExecute")
            except OSError:
                return findings

            entries = val if isinstance(val, list) else [str(val)]
            for entry in entries:
                entry = entry.strip()
                if entry.lower() not in _NORMAL_BOOT_EXECUTE:
                    findings.append({
                        "severity": "HIGH",
                        "reason":   (f"Non-standard BootExecute entry: '{entry}' — "
                                     r"possible bootkit persistence "
                                     r"(HKLM\SYSTEM\...\Session Manager)"),
                        "name":     "BootExecute",
                        "location": rf"HKLM\{key_path}",
                    })
    except Exception as exc:
        log.debug("BootExecute scan failed: %s", exc)
    return findings


# -----------------------------------------------------------------------
# 5. Services with suspicious binary paths
# -----------------------------------------------------------------------

# Service types: 1=KERNEL_DRIVER, 2=FILE_SYSTEM_DRIVER, 4=ADAPTER, 8=RECOGNIZER_DRIVER
# Only USER-MODE service types (16=OWN_PROCESS, 32=SHARE_PROCESS, 256=INTERACTIVE)
# are relevant for persistence via user-writable paths.
_USER_MODE_SERVICE_TYPES = {16, 32, 256, 272, 288}


def _scan_suspicious_services() -> list[dict]:
    """
    Flag user-mode services whose ImagePath points to temp/user-writable dirs.
    Double-check: signature-verified binaries are skipped.
    Kernel/FS driver types are excluded (different threat model).
    """
    findings: list[dict] = []
    svc_key = r"SYSTEM\CurrentControlSet\Services"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, svc_key) as root:
            i = 0
            while True:
                try:
                    svc_name = winreg.EnumKey(root, i)
                    i += 1
                except OSError:
                    break

                try:
                    with winreg.OpenKey(root, svc_name) as sk:
                        try:
                            image_path, _ = winreg.QueryValueEx(sk, "ImagePath")
                        except OSError:
                            continue
                        # Read service type
                        try:
                            svc_type, _ = winreg.QueryValueEx(sk, "Type")
                        except OSError:
                            svc_type = 0

                    # Skip kernel-mode driver types
                    if int(svc_type) not in _USER_MODE_SERVICE_TYPES:
                        continue

                    image_path = os.path.expandvars(
                        str(image_path).strip('"').strip()
                    )
                    if not _is_suspicious_path(image_path.lower()):
                        continue

                    # Double-check: trusted signature overrides suspicious path
                    exe = _extract_exe(image_path)
                    if _is_trusted_signature(exe or image_path):
                        log.debug("Service '%s': suspicious path but trusted signature — skipped", svc_name)
                        continue

                    findings.append({
                        "severity": "HIGH",
                        "reason":   (f"Service '{svc_name}' binary at suspicious path: "
                                     f"{image_path} — unsigned / unrecognised publisher"),
                        "name":     svc_name,
                        "location": image_path,
                    })
                except Exception:
                    pass
    except Exception as exc:
        log.debug("Services persistence scan failed: %s", exc)
    return findings


# -----------------------------------------------------------------------
# 6. AppInit_DLLs and LSA notification / security packages
# -----------------------------------------------------------------------

# Well-known default LSA packages shipped with Windows
_SAFE_LSA_PACKAGES: set[str] = {
    "rassfm", "scecli", "wdigest", "tspkg", "pku2u",
    "livessp", "cloudap", "msv1_0", "kerberos", "negoexts",
    "kdcsvc",
}

_SYSTEM32 = os.environ.get("SystemRoot", r"C:\Windows") + r"\System32\\"


def _scan_registry_dll_injection() -> list[dict]:
    """
    Check AppInit_DLLs and LSA packages for unexpected DLL injection vectors.
    Double-checks:
      • DLL must actually exist on disk
      • DLL in System32 is treated as lower-risk (still reported, severity MEDIUM)
      • DLL signed by trusted publisher is skipped
    """
    findings: list[dict] = []

    checks = [
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "AppInit_DLLs",
            "AppInit_DLLs",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "Notification Packages",
            "LSA Notification Package",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "Security Packages",
            "LSA Security Package",
        ),
    ]

    for hive, key_path, value_name, label in checks:
        try:
            with winreg.OpenKey(hive, key_path) as k:
                try:
                    val, _ = winreg.QueryValueEx(k, value_name)
                except OSError:
                    continue

            raw = val if isinstance(val, list) else str(val).split("\x00")
            # Strip whitespace, surrounding quotes, null chars; drop empties
            entries = [e.strip().strip('"').strip("'").strip() for e in raw]
            entries = [e for e in entries if e and len(e) > 1]

            for entry in entries:
                entry_l = entry.lower()
                if entry_l in _SAFE_LSA_PACKAGES:
                    continue

                # Resolve to a full path if not already absolute
                if not os.path.isabs(entry):
                    candidates = [
                        os.path.join(_SYSTEM32, entry),
                        os.path.join(_SYSTEM32, entry + ".dll"),
                    ]
                    full_path = next(
                        (c for c in candidates if os.path.isfile(c)), None
                    )
                else:
                    full_path = entry if os.path.isfile(entry) else None

                # Double-check: file doesn't exist → HIGH (dropped by malware)
                # File in System32 → check signature
                # File elsewhere   → HIGH regardless

                if full_path is None:
                    findings.append({
                        "severity": "HIGH",
                        "reason":   (f"{label}: '{entry}' registered but DLL not found on disk "
                                     f"— possible remnant of malware or corrupted entry "
                                     f"(HKLM\\{key_path}\\{value_name})"),
                        "name":     entry,
                        "location": rf"HKLM\{key_path}",
                    })
                    continue

                if _is_trusted_signature(full_path):
                    log.debug("%s '%s': trusted signature — skipped", label, entry)
                    continue

                in_system32 = full_path.lower().startswith(_SYSTEM32.lower())
                sev = "MEDIUM" if in_system32 else "HIGH"
                findings.append({
                    "severity": sev,
                    "reason":   (f"{label}: '{entry}' at {full_path} — "
                                 f"not signed by a known publisher; verify legitimacy "
                                 f"(HKLM\\{key_path}\\{value_name})"),
                    "name":     entry,
                    "location": full_path,
                })

        except Exception as exc:
            log.debug("%s scan failed: %s", label, exc)

    return findings


# -----------------------------------------------------------------------
# Public entry point
# -----------------------------------------------------------------------

def _rag_filter(findings: list[dict]) -> list[dict]:
    """Post-filter findings through the RAG knowledge base."""
    if not _RAG_AVAILABLE or _rag is None:
        return findings
    kept: list[dict] = []
    for f in findings:
        is_benign, conf, reason = _rag.check(
            name=f.get("name", ""),
            path=f.get("location", ""),
            publisher="",
            kind="persistence",
        )
        if is_benign and conf >= 0.75:
            log.debug("RAG suppressed finding '%s': %s (conf=%.2f)",
                      f.get("name", ""), reason, conf)
        else:
            kept.append(f)
    suppressed = len(findings) - len(kept)
    if suppressed:
        log.info("RAG filter suppressed %d false positive(s)", suppressed)
    return kept


def scan_persistence() -> list[dict]:
    """Run all persistence checks and return combined findings."""
    findings: list[dict] = []
    findings += _scan_scheduled_tasks()
    findings += _scan_wmi_subscriptions()
    findings += _scan_startup_folders()
    findings += _scan_boot_execute()
    findings += _scan_suspicious_services()
    findings += _scan_registry_dll_injection()
    findings = _rag_filter(findings)
    log.info("Persistence scan: %d finding(s)", len(findings))
    return findings
