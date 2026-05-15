"""
Built-in labeled training dataset for the rootkit threat classifier.

Each sample: (reason_text, scan_type, severity, port, name, label)
  reason_text : string matching what the scanner produces
  scan_type   : "Process" | "Driver" | "Network" | "Registry" | "Memory"
  severity    : "HIGH" | "MEDIUM" | "LOW" | "INFO"
  port        : int (0 if not applicable)
  name        : process/driver/value name (lowercase)
  label       : threat category string

This dataset is hand-crafted from known malware behaviors, public threat
reports, and the detection patterns implemented in this scanner.
Augment it with Kaggle data using: python ml_model/train.py --kaggle
"""

SAMPLES: list[tuple] = [

    # ------------------------------------------------------------------ PROCESS_HIDING
    ("Process 'explorer.exe' (PID 4512) visible in psutil but hidden from: WMIC", "Process", "HIGH", 0, "explorer.exe", "PROCESS_HIDING"),
    ("Process 'svchost.exe' (PID 7890) visible in psutil but hidden from: tasklist", "Process", "HIGH", 0, "svchost.exe", "PROCESS_HIDING"),
    ("Process 'cmd.exe' (PID 3300) visible in psutil but hidden from: WMIC, tasklist", "Process", "HIGH", 0, "cmd.exe", "PROCESS_HIDING"),
    ("PID 9911 persistently visible in WMIC but absent from psutil on multiple checks (possible kernel-level evasion)", "Process", "HIGH", 0, "<unknown>", "PROCESS_HIDING"),
    ("PID 1188 persistently visible in WMIC but absent from psutil on multiple checks (possible kernel-level evasion)", "Process", "HIGH", 0, "<unknown>", "PROCESS_HIDING"),
    ("Process 'powershell.exe' (PID 6672) visible in psutil but hidden from: WMIC", "Process", "HIGH", 0, "powershell.exe", "PROCESS_HIDING"),
    ("Process 'wscript.exe' (PID 2240) visible in psutil but hidden from: WMIC, tasklist", "Process", "HIGH", 0, "wscript.exe", "PROCESS_HIDING"),
    ("Process 'mshta.exe' (PID 5540) visible in psutil but hidden from: tasklist", "Process", "HIGH", 0, "mshta.exe", "PROCESS_HIDING"),
    ("PID 18432 persistently visible in WMIC but absent from psutil on multiple checks (possible kernel-level evasion)", "Process", "HIGH", 0, "<unknown>", "PROCESS_HIDING"),
    ("Process 'regsvr32.exe' (PID 3312) visible in psutil but hidden from: WMIC", "Process", "HIGH", 0, "regsvr32.exe", "PROCESS_HIDING"),
    ("Process 'rundll32.exe' (PID 4448) visible in psutil but hidden from: WMIC, tasklist", "Process", "HIGH", 0, "rundll32.exe", "PROCESS_HIDING"),
    ("PID 22100 persistently visible in WMIC but absent from psutil on multiple checks (possible kernel-level evasion)", "Process", "HIGH", 0, "<unknown>", "PROCESS_HIDING"),
    ("Process 'dllhost.exe' (PID 8812) visible in psutil but hidden from: WMIC", "Process", "HIGH", 0, "dllhost.exe", "PROCESS_HIDING"),
    ("Process 'conhost.exe' (PID 7778) visible in psutil but hidden from: tasklist", "Process", "HIGH", 0, "conhost.exe", "PROCESS_HIDING"),
    ("Process 'notepad.exe' (PID 5114) visible in psutil but hidden from: WMIC", "Process", "HIGH", 0, "notepad.exe", "PROCESS_HIDING"),
    ("PID 55321 persistently visible in WMIC but absent from psutil on multiple checks (possible kernel-level evasion)", "Process", "HIGH", 0, "<unknown>", "PROCESS_HIDING"),
    ("Process 'csc.exe' (PID 9988) visible in psutil but hidden from: WMIC, tasklist", "Process", "HIGH", 0, "csc.exe", "PROCESS_HIDING"),
    ("Process 'certutil.exe' (PID 7761) visible in psutil but hidden from: WMIC", "Process", "HIGH", 0, "certutil.exe", "PROCESS_HIDING"),
    ("PID 4096 persistently visible in WMIC but absent from psutil on multiple checks (possible kernel-level evasion)", "Process", "HIGH", 0, "<unknown>", "PROCESS_HIDING"),
    ("Process 'msiexec.exe' (PID 3344) visible in psutil but hidden from: tasklist", "Process", "HIGH", 0, "msiexec.exe", "PROCESS_HIDING"),

    # ------------------------------------------------------------------ PROCESS_MASQUERADE
    ("Masquerade: 'svchost.exe' running from C:\\Users\\Public\\svchost.exe (expected C:\\Windows\\System32)", "Process", "HIGH", 0, "svchost.exe", "PROCESS_MASQUERADE"),
    ("Masquerade: 'lsass.exe' running from C:\\Temp\\lsass.exe (expected C:\\Windows\\System32)", "Process", "HIGH", 0, "lsass.exe", "PROCESS_MASQUERADE"),
    ("Masquerade: 'explorer.exe' running from C:\\Users\\user\\AppData\\Roaming\\explorer.exe", "Process", "HIGH", 0, "explorer.exe", "PROCESS_MASQUERADE"),
    ("Masquerade: 'csrss.exe' running from C:\\Windows\\Temp\\csrss.exe (expected C:\\Windows\\System32)", "Process", "HIGH", 0, "csrss.exe", "PROCESS_MASQUERADE"),
    ("Masquerade: 'winlogon.exe' running from C:\\Temp\\winlogon.exe (wrong path)", "Process", "HIGH", 0, "winlogon.exe", "PROCESS_MASQUERADE"),
    ("Masquerade: 'services.exe' running from C:\\Users\\user\\Downloads\\services.exe", "Process", "HIGH", 0, "services.exe", "PROCESS_MASQUERADE"),
    ("Masquerade: 'taskmgr.exe' running from C:\\ProgramData\\taskmgr.exe (wrong path)", "Process", "HIGH", 0, "taskmgr.exe", "PROCESS_MASQUERADE"),
    ("Masquerade: 'svchost.exe' running from C:\\Windows\\Temp\\svchost.exe", "Process", "HIGH", 0, "svchost.exe", "PROCESS_MASQUERADE"),
    ("Masquerade: 'spoolsv.exe' running from C:\\Users\\Public\\spoolsv.exe", "Process", "HIGH", 0, "spoolsv.exe", "PROCESS_MASQUERADE"),
    ("Masquerade: 'wininit.exe' running from C:\\Temp\\wininit.exe (expected C:\\Windows\\System32)", "Process", "HIGH", 0, "wininit.exe", "PROCESS_MASQUERADE"),
    ("Masquerade: 'smss.exe' running from C:\\Windows\\Temp\\smss.exe", "Process", "HIGH", 0, "smss.exe", "PROCESS_MASQUERADE"),
    ("Masquerade: 'lsaiso.exe' running from C:\\Users\\user\\AppData\\Local\\lsaiso.exe", "Process", "HIGH", 0, "lsaiso.exe", "PROCESS_MASQUERADE"),
    ("Masquerade: 'dwm.exe' running from C:\\Temp\\dwm.exe (wrong location)", "Process", "HIGH", 0, "dwm.exe", "PROCESS_MASQUERADE"),
    ("Masquerade: 'taskhost.exe' running from C:\\Users\\user\\taskhost.exe", "Process", "HIGH", 0, "taskhost.exe", "PROCESS_MASQUERADE"),
    ("Masquerade: 'ctfmon.exe' running from C:\\ProgramData\\ctfmon.exe (wrong location)", "Process", "HIGH", 0, "ctfmon.exe", "PROCESS_MASQUERADE"),

    # ------------------------------------------------------------------ PARENT_ANOMALY
    ("Suspicious parent: svchost.exe (PID 4400) is parented by explorer.exe (PID 1234) -- expected one of: ['services.exe']", "Process", "HIGH", 0, "svchost.exe", "PARENT_ANOMALY"),
    ("Suspicious parent: lsass.exe (PID 700) is parented by cmd.exe (PID 2200) -- expected one of: ['wininit.exe']", "Process", "HIGH", 0, "lsass.exe", "PARENT_ANOMALY"),
    ("Suspicious parent: services.exe (PID 660) is parented by powershell.exe (PID 9910) -- expected one of: ['wininit.exe']", "Process", "HIGH", 0, "services.exe", "PARENT_ANOMALY"),
    ("Suspicious parent: csrss.exe (PID 524) is parented by explorer.exe (PID 1000) -- expected one of: ['smss.exe']", "Process", "HIGH", 0, "csrss.exe", "PARENT_ANOMALY"),
    ("Suspicious parent: winlogon.exe (PID 540) is parented by svchost.exe (PID 1100) -- expected one of: ['smss.exe']", "Process", "HIGH", 0, "winlogon.exe", "PARENT_ANOMALY"),
    ("Suspicious parent: explorer.exe (PID 3000) is parented by cmd.exe (PID 5544) -- expected one of: ['userinit.exe', 'winlogon.exe']", "Process", "HIGH", 0, "explorer.exe", "PARENT_ANOMALY"),
    ("Suspicious parent: spoolsv.exe (PID 1800) is parented by powershell.exe (PID 4400) -- expected one of: ['services.exe']", "Process", "HIGH", 0, "spoolsv.exe", "PARENT_ANOMALY"),
    ("Suspicious parent: wininit.exe (PID 436) is parented by explorer.exe (PID 3300) -- expected one of: ['smss.exe']", "Process", "HIGH", 0, "wininit.exe", "PARENT_ANOMALY"),
    ("Suspicious parent: svchost.exe (PID 5500) is parented by mshta.exe (PID 7890) -- expected one of: ['services.exe']", "Process", "HIGH", 0, "svchost.exe", "PARENT_ANOMALY"),
    ("Suspicious parent: lsass.exe (PID 700) is parented by rundll32.exe (PID 3312) -- expected one of: ['wininit.exe']", "Process", "HIGH", 0, "lsass.exe", "PARENT_ANOMALY"),
    ("Suspicious parent: taskhostw.exe (PID 2240) is parented by cmd.exe (PID 8812) -- expected one of: ['services.exe', 'svchost.exe']", "Process", "HIGH", 0, "taskhostw.exe", "PARENT_ANOMALY"),

    # ------------------------------------------------------------------ TEMP_EXECUTION
    ("Executable in suspicious directory: PID 4410 'update.exe' running from C:\\Users\\user\\AppData\\Local\\Temp\\", "Process", "HIGH", 0, "update.exe", "TEMP_EXECUTION"),
    ("Executable in suspicious directory: PID 3311 'install.exe' running from C:\\Windows\\Temp\\", "Process", "HIGH", 0, "install.exe", "TEMP_EXECUTION"),
    ("Executable in suspicious directory: PID 5500 'patch.exe' running from C:\\Users\\Public\\", "Process", "HIGH", 0, "patch.exe", "TEMP_EXECUTION"),
    ("Executable in suspicious directory: PID 7710 'helper.exe' running from C:\\Temp\\", "Process", "HIGH", 0, "helper.exe", "TEMP_EXECUTION"),
    ("Executable in suspicious directory: PID 2200 'setup.exe' running from C:\\Users\\user\\Downloads\\", "Process", "MEDIUM", 0, "setup.exe", "TEMP_EXECUTION"),
    ("Executable in suspicious directory: PID 1100 'run.exe' running from C:\\Users\\user\\Desktop\\", "Process", "MEDIUM", 0, "run.exe", "TEMP_EXECUTION"),
    ("Executable in suspicious directory: PID 8890 'loader.exe' running from C:\\Users\\user\\AppData\\Roaming\\", "Process", "HIGH", 0, "loader.exe", "TEMP_EXECUTION"),
    ("Executable in suspicious directory: PID 3332 'agent.exe' running from C:\\ProgramData\\Updates\\", "Process", "HIGH", 0, "agent.exe", "TEMP_EXECUTION"),
    ("Executable in suspicious directory: PID 6610 'payload.exe' running from C:\\Users\\user\\AppData\\Local\\Temp\\pkg\\", "Process", "HIGH", 0, "payload.exe", "TEMP_EXECUTION"),
    ("Executable in suspicious directory: PID 9901 'dropper.exe' running from C:\\Windows\\Temp\\cab001\\", "Process", "HIGH", 0, "dropper.exe", "TEMP_EXECUTION"),

    # ------------------------------------------------------------------ DLL_INJECTION
    ("Suspicious DLL loaded: PID 820 'lsass.exe' loaded 'C:\\Users\\user\\AppData\\Local\\Temp\\inject.dll'", "Process", "HIGH", 0, "lsass.exe", "DLL_INJECTION"),
    ("Suspicious DLL loaded: PID 3300 'explorer.exe' loaded 'C:\\Windows\\Temp\\hook.dll'", "Process", "HIGH", 0, "explorer.exe", "DLL_INJECTION"),
    ("Suspicious DLL loaded: PID 5540 'svchost.exe' loaded 'C:\\Users\\Public\\spy.dll'", "Process", "HIGH", 0, "svchost.exe", "DLL_INJECTION"),
    ("Suspicious DLL loaded: PID 4400 'notepad.exe' loaded 'C:\\Temp\\rat.dll'", "Process", "HIGH", 0, "notepad.exe", "DLL_INJECTION"),
    ("Suspicious DLL loaded: PID 2200 'chrome.exe' loaded 'C:\\Users\\user\\Downloads\\ext.dll'", "Process", "MEDIUM", 0, "chrome.exe", "DLL_INJECTION"),
    ("Suspicious DLL loaded: PID 7780 'taskhost.exe' loaded 'C:\\ProgramData\\update\\patch.dll'", "Process", "HIGH", 0, "taskhost.exe", "DLL_INJECTION"),
    ("Suspicious DLL loaded: PID 3312 'services.exe' loaded 'C:\\Users\\user\\AppData\\Roaming\\hook.dll'", "Process", "HIGH", 0, "services.exe", "DLL_INJECTION"),
    ("Suspicious DLL loaded: PID 8812 'winlogon.exe' loaded 'C:\\Windows\\Temp\\persist.dll'", "Process", "HIGH", 0, "winlogon.exe", "DLL_INJECTION"),
    ("Suspicious DLL loaded: PID 9910 'spoolsv.exe' loaded 'C:\\Temp\\payload.dll'", "Process", "HIGH", 0, "spoolsv.exe", "DLL_INJECTION"),

    # ------------------------------------------------------------------ DRIVER_HIDDEN
    ("Driver 'rootkit.sys' visible in registry but absent from driverquery output", "Driver", "HIGH", 0, "rootkit.sys", "DRIVER_HIDDEN"),
    ("Driver 'hider.sys' visible in driverquery but absent from registry scan", "Driver", "HIGH", 0, "hider.sys", "DRIVER_HIDDEN"),
    ("Driver 'injector.sys' absent from driverquery but present in registry services", "Driver", "HIGH", 0, "injector.sys", "DRIVER_HIDDEN"),
    ("Driver 'kdfix.sys' hidden from Windows driver enumeration API but visible via raw scan", "Driver", "HIGH", 0, "kdfix.sys", "DRIVER_HIDDEN"),
    ("Driver 'net_hide.sys' present in kernel module list but absent from registry", "Driver", "HIGH", 0, "net_hide.sys", "DRIVER_HIDDEN"),
    ("Driver 'filtr.sys' visible in raw registry scan but not in standard driver list", "Driver", "HIGH", 0, "filtr.sys", "DRIVER_HIDDEN"),
    ("Driver 'bypass.sys' present in Volatility modules but missing from driverquery", "Driver", "HIGH", 0, "bypass.sys", "DRIVER_HIDDEN"),
    ("Driver 'stealth.sys' loaded in kernel address space but not enumerable via standard API", "Driver", "HIGH", 0, "stealth.sys", "DRIVER_HIDDEN"),

    # ------------------------------------------------------------------ DRIVER_SUSPICIOUS
    ("Driver 'update_drv.sys' loaded from unusual location: C:\\Users\\user\\AppData\\Local\\update_drv.sys", "Driver", "HIGH", 0, "update_drv.sys", "DRIVER_SUSPICIOUS"),
    ("Driver 'spy_kernel.sys' not signed — no valid digital signature found", "Driver", "HIGH", 0, "spy_kernel.sys", "DRIVER_SUSPICIOUS"),
    ("Driver 'malware.sys' loaded from C:\\Temp\\malware.sys — outside standard driver directories", "Driver", "HIGH", 0, "malware.sys", "DRIVER_SUSPICIOUS"),
    ("Driver 'payload_drv.sys' has expired or revoked code signing certificate", "Driver", "HIGH", 0, "payload_drv.sys", "DRIVER_SUSPICIOUS"),
    ("Driver 'suspicious.sys' loaded from C:\\ProgramData\\suspicious.sys — non-standard path", "Driver", "HIGH", 0, "suspicious.sys", "DRIVER_SUSPICIOUS"),
    ("Driver 'unverified.sys' loaded from C:\\Users\\Public\\Drivers\\unverified.sys", "Driver", "HIGH", 0, "unverified.sys", "DRIVER_SUSPICIOUS"),
    ("Driver 'tempdrv.sys' loaded from C:\\Windows\\Temp\\tempdrv.sys — suspicious temp location", "Driver", "HIGH", 0, "tempdrv.sys", "DRIVER_SUSPICIOUS"),
    ("Unsigned kernel driver detected: 'nologo.sys' at C:\\Program Files\\UnknownApp\\nologo.sys", "Driver", "MEDIUM", 0, "nologo.sys", "DRIVER_SUSPICIOUS"),
    ("Driver 'cracked.sys' loaded from C:\\Downloads\\cracked.sys — suspicious path", "Driver", "HIGH", 0, "cracked.sys", "DRIVER_SUSPICIOUS"),
    ("Driver 'hook_drv.sys' not in standard Windows driver paths and missing digital signature", "Driver", "HIGH", 0, "hook_drv.sys", "DRIVER_SUSPICIOUS"),
    ("Driver 'filterdrv.sys' loaded from unusual path C:\\Users\\user\\filterdrv.sys", "Driver", "MEDIUM", 0, "filterdrv.sys", "DRIVER_SUSPICIOUS"),

    # ------------------------------------------------------------------ NETWORK_HIDING
    ("TCP port 4444 LISTEN visible in psutil but absent from netstat - possible socket hook", "Network", "HIGH", 4444, "<unknown>", "NETWORK_HIDING"),
    ("TCP port 9090 LISTEN visible in netstat but absent from psutil - possible kernel-level evasion", "Network", "HIGH", 9090, "<unknown>", "NETWORK_HIDING"),
    ("TCP port 1234 LISTEN visible in psutil but absent from netstat - possible socket hook", "Network", "HIGH", 1234, "<unknown>", "NETWORK_HIDING"),
    ("TCP port 6666 LISTEN visible in netstat but absent from psutil - possible kernel-level evasion", "Network", "HIGH", 6666, "<unknown>", "NETWORK_HIDING"),
    ("TCP port 8181 LISTEN visible in psutil but absent from netstat - possible socket hook", "Network", "HIGH", 8181, "<unknown>", "NETWORK_HIDING"),
    ("TCP port 3333 LISTEN visible in netstat but absent from psutil - possible kernel-level evasion", "Network", "HIGH", 3333, "<unknown>", "NETWORK_HIDING"),
    ("TCP port 7777 LISTEN visible in psutil but absent from netstat - possible socket hook", "Network", "HIGH", 7777, "<unknown>", "NETWORK_HIDING"),
    ("TCP port 2222 LISTEN visible in netstat but absent from psutil - possible kernel-level evasion", "Network", "HIGH", 2222, "<unknown>", "NETWORK_HIDING"),
    ("TCP port 5555 LISTEN visible in psutil but absent from netstat - possible socket hook", "Network", "HIGH", 5555, "<unknown>", "NETWORK_HIDING"),

    # ------------------------------------------------------------------ MALWARE_PORT
    ("Connection on known malware port 4444 owned by meterpreter.exe (PID 7890)", "Network", "MEDIUM", 4444, "meterpreter.exe", "MALWARE_PORT"),
    ("Connection on known malware port 1337 owned by implant.exe (PID 3312)", "Network", "MEDIUM", 1337, "implant.exe", "MALWARE_PORT"),
    ("Connection on known malware port 31337 owned by backdoor.exe (PID 5500)", "Network", "MEDIUM", 31337, "backdoor.exe", "MALWARE_PORT"),
    ("Connection on known malware port 9001 owned by tor_proxy.exe (PID 4410)", "Network", "MEDIUM", 9001, "tor_proxy.exe", "MALWARE_PORT"),
    ("Connection on known malware port 6667 owned by irc_bot.exe (PID 2200)", "Network", "MEDIUM", 6667, "irc_bot.exe", "MALWARE_PORT"),
    ("Connection on known malware port 12345 owned by remote_access.exe (PID 8812)", "Network", "MEDIUM", 12345, "remote_access.exe", "MALWARE_PORT"),
    ("Connection on known malware port 4445 owned by c2client.exe (PID 7710)", "Network", "MEDIUM", 4445, "c2client.exe", "MALWARE_PORT"),
    ("Connection on known malware port 5554 owned by worm.exe (PID 1100)", "Network", "MEDIUM", 5554, "worm.exe", "MALWARE_PORT"),
    ("Connection on known malware port 54321 owned by payload.exe (PID 9910)", "Network", "MEDIUM", 54321, "payload.exe", "MALWARE_PORT"),
    ("Connection on known malware port 9050 owned by proxy_relay.exe (PID 3332)", "Network", "MEDIUM", 9050, "proxy_relay.exe", "MALWARE_PORT"),
    ("Connection on known malware port 6697 owned by ircbot.exe (PID 6610)", "Network", "MEDIUM", 6697, "ircbot.exe", "MALWARE_PORT"),
    ("Connection on known malware port 2222 owned by ssh_tunnel.exe (PID 4448)", "Network", "MEDIUM", 2222, "ssh_tunnel.exe", "MALWARE_PORT"),
    ("Connection on known malware port 1338 owned by c2agent.exe (PID 9901)", "Network", "MEDIUM", 1338, "c2agent.exe", "MALWARE_PORT"),
    ("Connection on known malware port 8888 owned by webshell_srv.exe (PID 3300)", "Network", "MEDIUM", 8888, "webshell_srv.exe", "MALWARE_PORT"),

    # ------------------------------------------------------------------ ORPHAN_SOCKET
    ("Socket on port 4444 has no owning process (orphan socket)", "Network", "MEDIUM", 4444, "<unknown>", "ORPHAN_SOCKET"),
    ("Socket on port 9000 has no owning process (orphan socket)", "Network", "MEDIUM", 9000, "<unknown>", "ORPHAN_SOCKET"),
    ("Socket on port 1337 has no owning process (orphan socket)", "Network", "MEDIUM", 1337, "<unknown>", "ORPHAN_SOCKET"),
    ("Socket on port 8181 has no owning process (orphan socket)", "Network", "MEDIUM", 8181, "<unknown>", "ORPHAN_SOCKET"),
    ("Socket on port 3128 has no owning process (orphan socket)", "Network", "MEDIUM", 3128, "<unknown>", "ORPHAN_SOCKET"),
    ("Socket on port 6666 has no owning process (orphan socket)", "Network", "MEDIUM", 6666, "<unknown>", "ORPHAN_SOCKET"),
    ("Socket on port 31337 has no owning process (orphan socket)", "Network", "MEDIUM", 31337, "<unknown>", "ORPHAN_SOCKET"),
    ("Socket on port 443 has no owning process (orphan socket)", "Network", "MEDIUM", 443, "<unknown>", "ORPHAN_SOCKET"),

    # ------------------------------------------------------------------ REGISTRY_PERSISTENCE
    ("Autorun entry in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run: 'malware' -> C:\\Users\\user\\AppData\\Roaming\\malware.exe", "Registry", "HIGH", 0, "malware", "REGISTRY_PERSISTENCE"),
    ("Autorun entry in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run: 'updater' -> C:\\Temp\\updater.exe", "Registry", "HIGH", 0, "updater", "REGISTRY_PERSISTENCE"),
    ("Autorun entry in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce: 'loader' -> C:\\Windows\\Temp\\loader.exe", "Registry", "HIGH", 0, "loader", "REGISTRY_PERSISTENCE"),
    ("Autorun entry in HKCU Run: 'svcupdate' -> C:\\Users\\user\\Downloads\\svcupdate.exe", "Registry", "HIGH", 0, "svcupdate", "REGISTRY_PERSISTENCE"),
    ("Autorun entry in HKLM Run: 'security_patch' -> C:\\ProgramData\\security_patch.exe", "Registry", "HIGH", 0, "security_patch", "REGISTRY_PERSISTENCE"),
    ("Autorun entry in HKCU Run: 'helper' -> C:\\Users\\Public\\helper.exe", "Registry", "HIGH", 0, "helper", "REGISTRY_PERSISTENCE"),
    ("Autorun entry in HKLM Run: 'win_update' -> C:\\Windows\\Temp\\win_update.exe (suspicious temp path)", "Registry", "HIGH", 0, "win_update", "REGISTRY_PERSISTENCE"),
    ("Autorun entry in HKCU Run: 'agent' -> C:\\Users\\user\\AppData\\Local\\agent.exe", "Registry", "HIGH", 0, "agent", "REGISTRY_PERSISTENCE"),
    ("Autorun entry in HKLM Run: 'monitor' -> C:\\Temp\\monitor.exe", "Registry", "HIGH", 0, "monitor", "REGISTRY_PERSISTENCE"),
    ("Autorun entry in HKCU Run: 'dropper' -> C:\\Users\\user\\Desktop\\dropper.exe", "Registry", "MEDIUM", 0, "dropper", "REGISTRY_PERSISTENCE"),
    ("Startup entry pointing to unknown executable in non-standard path: C:\\ProgramData\\svc32.exe", "Registry", "HIGH", 0, "svc32", "REGISTRY_PERSISTENCE"),

    # ------------------------------------------------------------------ REGISTRY_WINLOGON
    ("Winlogon hijack: 'Userinit' value set to 'C:\\Windows\\system32\\userinit.exe, C:\\Temp\\init.exe'", "Registry", "HIGH", 0, "userinit", "REGISTRY_WINLOGON"),
    ("Winlogon hijack: 'Shell' value changed to 'explorer.exe C:\\Users\\user\\AppData\\payload.exe'", "Registry", "HIGH", 0, "shell", "REGISTRY_WINLOGON"),
    ("Winlogon 'Notify' key has unexpected DLL: C:\\Windows\\Temp\\notify.dll", "Registry", "HIGH", 0, "notify", "REGISTRY_WINLOGON"),
    ("Winlogon hijack: 'Userinit' replaced with C:\\Temp\\fake_userinit.exe", "Registry", "HIGH", 0, "userinit", "REGISTRY_WINLOGON"),
    ("Winlogon 'Shell' hijacked: replaced explorer.exe with malicious shell C:\\ProgramData\\shell.exe", "Registry", "HIGH", 0, "shell", "REGISTRY_WINLOGON"),
    ("Suspicious Winlogon key: 'AppSetup' value pointing to C:\\Temp\\appsetup.dll", "Registry", "HIGH", 0, "appsetup", "REGISTRY_WINLOGON"),
    ("Winlogon 'UserInit' modified to load additional executable at C:\\Users\\user\\AppData\\Roaming\\persist.exe", "Registry", "HIGH", 0, "userinit", "REGISTRY_WINLOGON"),

    # ------------------------------------------------------------------ REGISTRY_IFEO
    ("IFEO Debugger hijack: taskmgr.exe will be intercepted by C:\\Temp\\fake_taskmgr.exe", "Registry", "HIGH", 0, "taskmgr.exe", "REGISTRY_IFEO"),
    ("IFEO Debugger hijack: regedit.exe will be intercepted by C:\\Windows\\Temp\\blocker.exe", "Registry", "HIGH", 0, "regedit.exe", "REGISTRY_IFEO"),
    ("IFEO Debugger set for msconfig.exe -> C:\\Users\\user\\AppData\\spy.exe", "Registry", "HIGH", 0, "msconfig.exe", "REGISTRY_IFEO"),
    ("IFEO key found for cmd.exe with Debugger C:\\Temp\\cmd_hook.exe", "Registry", "HIGH", 0, "cmd.exe", "REGISTRY_IFEO"),
    ("IFEO Debugger hijack: procexp.exe replaced by C:\\ProgramData\\antidebug.exe", "Registry", "HIGH", 0, "procexp.exe", "REGISTRY_IFEO"),
    ("IFEO key: 'Debugger' set for mmc.exe -> C:\\Temp\\mmc_trap.exe", "Registry", "HIGH", 0, "mmc.exe", "REGISTRY_IFEO"),
    ("Image File Execution Options abuse: svchost.exe debugger set to C:\\Users\\user\\AppData\\Roaming\\monitor.exe", "Registry", "HIGH", 0, "svchost.exe", "REGISTRY_IFEO"),

    # ------------------------------------------------------------------ MEMORY_INJECTION
    ("Malfind: PID 820 'lsass.exe' has executable region at 0x00400000 with PAGE_EXECUTE_READWRITE", "Memory", "HIGH", 0, "lsass.exe", "MEMORY_INJECTION"),
    ("Malfind: PID 4 'System' has injected PE at 0x7ff80000 - MZ header detected in data region", "Memory", "HIGH", 0, "system", "MEMORY_INJECTION"),
    ("Malfind: PID 3300 'explorer.exe' has shellcode at 0x1a2b3c00 (PAGE_EXECUTE_READWRITE, no backing file)", "Memory", "HIGH", 0, "explorer.exe", "MEMORY_INJECTION"),
    ("Malfind: PID 1000 'svchost.exe' private executable memory at 0x00900000 outside any module", "Memory", "HIGH", 0, "svchost.exe", "MEMORY_INJECTION"),
    ("Injected PE detected in 'notepad.exe' (PID 5114) at address 0x004f0000 via malfind", "Memory", "HIGH", 0, "notepad.exe", "MEMORY_INJECTION"),
    ("Process hollowing detected: 'svchost.exe' base image replaced at 0x00010000", "Memory", "HIGH", 0, "svchost.exe", "MEMORY_INJECTION"),
    ("Malfind: PID 7890 'chrome.exe' has executable heap allocation with PE header at 0x50000000", "Memory", "HIGH", 0, "chrome.exe", "MEMORY_INJECTION"),
    ("Malfind: PID 2240 'iexplore.exe' reflective DLL injection detected at 0x30000000", "Memory", "HIGH", 0, "iexplore.exe", "MEMORY_INJECTION"),
    ("Memory injection: 'spoolsv.exe' (PID 1800) has PAGE_EXECUTE_READWRITE region with shellcode", "Memory", "HIGH", 0, "spoolsv.exe", "MEMORY_INJECTION"),
    ("Malfind: 'taskhost.exe' (PID 2240) has injected code blob at 0x10000000 (no path on disk)", "Memory", "HIGH", 0, "taskhost.exe", "MEMORY_INJECTION"),

    # ------------------------------------------------------------------ KERNEL_HOOK
    ("SSDT hook detected: NtOpenProcess redirected to 0xfffff80012340000 (unknown module)", "Memory", "HIGH", 0, "<kernel>", "KERNEL_HOOK"),
    ("SSDT hook: NtQuerySystemInformation hooked by module at 0xfffff80098760000 (not ntoskrnl)", "Memory", "HIGH", 0, "<kernel>", "KERNEL_HOOK"),
    ("IRP hook: \\Driver\\Disk IRP_MJ_READ dispatch replaced (not standard driver)", "Memory", "HIGH", 0, "<kernel>", "KERNEL_HOOK"),
    ("IRP hook: \\Driver\\Tcpip IRP_MJ_DEVICE_CONTROL replaced with unknown handler", "Memory", "HIGH", 0, "<kernel>", "KERNEL_HOOK"),
    ("SSDT hook: NtReadVirtualMemory hooked — anti-analysis or credential dumping likely", "Memory", "HIGH", 0, "<kernel>", "KERNEL_HOOK"),
    ("SSDT hook: NtWriteVirtualMemory redirected to rootkit module at high kernel address", "Memory", "HIGH", 0, "<kernel>", "KERNEL_HOOK"),
    ("Kernel DKOM: EPROCESS ActiveProcessLinks manipulated — process unlinking detected", "Memory", "HIGH", 0, "<kernel>", "KERNEL_HOOK"),
    ("IRP hook: \\Driver\\Null IRP_MJ_WRITE dispatch overwritten by foreign kernel code", "Memory", "HIGH", 0, "<kernel>", "KERNEL_HOOK"),
    ("SSDT hook: NtTerminateProcess redirected (likely anti-kill protection for malware process)", "Memory", "HIGH", 0, "<kernel>", "KERNEL_HOOK"),
    ("IRP hook: \\FileSystem\\Ntfs read IRP intercepted by unsigned driver at 0xfffff88009000000", "Memory", "HIGH", 0, "<kernel>", "KERNEL_HOOK"),

    # ------------------------------------------------------------------ BENIGN (false positives / known-good patterns)
    ("RzSDKServer.exe using port 1337 — Razer Synapse SDK (whitelisted)", "Network", "MEDIUM", 1337, "rzsdkserver.exe", "BENIGN"),
    ("taskhostw.exe parented by svchost.exe — normal on Windows 10/11 Task Scheduler", "Process", "HIGH", 0, "taskhostw.exe", "BENIGN"),
    ("OneDrive using IPv6 socket on port 42050 — normal cloud sync behavior", "Network", "MEDIUM", 42050, "onedrive.exe", "BENIGN"),
    ("Tor.exe using port 9050 — legitimate Tor browser (whitelisted)", "Network", "MEDIUM", 9050, "tor.exe", "BENIGN"),
    ("Python dev server on port 8080 — local development (whitelisted)", "Network", "MEDIUM", 8080, "python.exe", "BENIGN"),
    ("Fiddler proxy on port 8888 — known web debugging proxy (whitelisted)", "Network", "MEDIUM", 8888, "fiddler.exe", "BENIGN"),
    ("Driver 'hvax64.sys' from C:\\Windows\\System32\\drivers — standard Hyper-V driver", "Driver", "MEDIUM", 0, "hvax64.sys", "BENIGN"),
    ("Driver 'amdppm.sys' from C:\\Windows\\System32\\drivers — AMD processor power management", "Driver", "MEDIUM", 0, "amdppm.sys", "BENIGN"),
    ("Short-lived PID seen in WMIC during scan but gone after — likely ephemeral process", "Process", "HIGH", 0, "<unknown>", "BENIGN"),
    ("Discord autorun in HKCU Run pointing to C:\\Users\\user\\AppData\\Local\\Discord\\Update.exe", "Registry", "HIGH", 0, "discord", "BENIGN"),
    ("Slack startup entry in C:\\Users\\user\\AppData\\Local\\slack\\slack.exe", "Registry", "MEDIUM", 0, "slack", "BENIGN"),
    ("Node.js dev server on port 8080 — standard local development (whitelisted)", "Network", "MEDIUM", 8080, "node.exe", "BENIGN"),
    ("Java application on port 8888 — development/test environment (whitelisted)", "Network", "MEDIUM", 8888, "java.exe", "BENIGN"),
    ("Driver 'dbx.sys' from C:\\Windows\\System32\\drivers — signed Microsoft debug extension", "Driver", "MEDIUM", 0, "dbx.sys", "BENIGN"),
    ("Burp Suite proxy on port 8080 — authorized security testing tool (whitelisted)", "Network", "MEDIUM", 8080, "burpsuite.exe", "BENIGN"),
    ("Ephemeral PID visible in WMIC scan window only — disappeared on second check", "Process", "HIGH", 0, "<unknown>", "BENIGN"),
    ("Conhost launched per-session — normal Windows console host behavior", "Process", "HIGH", 0, "conhost.exe", "BENIGN"),
    ("WinRAR autorun in HKCU Run — user-installed legitimate compression tool", "Registry", "HIGH", 0, "winrar", "BENIGN"),
    ("Steam client autorun in HKCU Run — gaming platform (user-installed)", "Registry", "HIGH", 0, "steam", "BENIGN"),
    ("Brave browser autorun in HKCU Run pointing to Program Files", "Registry", "HIGH", 0, "brave", "BENIGN"),
]


KNOWN_SYSTEM_PROCESSES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "fontdrvhost.exe",
    "dwm.exe", "explorer.exe", "taskhost.exe", "taskhostw.exe", "conhost.exe",
    "spoolsv.exe", "msdtc.exe", "dllhost.exe", "taskeng.exe", "ctfmon.exe",
    "searchindexer.exe", "wuauclt.exe", "audiodg.exe", "sihost.exe",
    "runtimebroker.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
}

SCAN_TYPE_MAP = {"Process": 0, "Driver": 1, "Network": 2, "Registry": 3, "Memory": 4}
SEVERITY_MAP  = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
