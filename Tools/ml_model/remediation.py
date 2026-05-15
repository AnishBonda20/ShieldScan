"""
Remediation database — maps threat categories to actionable response steps,
MITRE ATT&CK technique references, and urgency levels.
"""

REMEDIATIONS: dict[str, dict] = {

    "PROCESS_HIDING": {
        "description": "A process is visible in one enumeration source but hidden from another. "
                       "This is a classic rootkit technique to conceal malicious activity.",
        "urgency": "IMMEDIATE",
        "mitre": ["T1014 - Rootkit", "T1055 - Process Injection"],
        "steps": [
            "1. DO NOT restart the system — volatile evidence will be lost.",
            "2. Take a full memory dump immediately (use DumpIt.exe bundled with this tool).",
            "3. Run Volatility3 'windows.pslist' and 'windows.psscan' to enumerate all processes.",
            "4. Compare results of psscan (raw pool scanning) vs pslist (EPROCESS walk).",
            "5. Identify the hidden PID and cross-reference with network connections (windows.netscan).",
            "6. Collect disk evidence: hash suspicious executables with 'certutil -hashfile <file> SHA256'.",
            "7. Submit hashes to VirusTotal or your EDR platform.",
            "8. Isolate the machine from the network immediately.",
            "9. Engage incident response — assume full system compromise.",
        ],
        "tools": ["DumpIt.exe", "Volatility3", "Process Hacker", "Autoruns (Sysinternals)"],
    },

    "PROCESS_MASQUERADE": {
        "description": "A process is using the name of a legitimate Windows system process "
                       "but is running from an unexpected directory. Common malware tactic.",
        "urgency": "HIGH",
        "mitre": ["T1036.005 - Masquerading: Match Legitimate Name or Location"],
        "steps": [
            "1. Note the full executable path from the scanner output.",
            "2. The real system processes should reside in C:\\Windows\\System32 or C:\\Windows\\SysWOW64.",
            "3. Hash the suspicious file: certutil -hashfile <path> SHA256",
            "4. Check the hash on VirusTotal: https://www.virustotal.com",
            "5. Check digital signature: right-click > Properties > Digital Signatures.",
            "6. If unsigned or unknown publisher — treat as malicious.",
            "7. Terminate the process via Task Manager or: taskkill /PID <pid> /F",
            "8. Delete the file after verifying no legitimate service depends on it.",
            "9. Run a full antivirus / EDR scan.",
            "10. Check startup locations (Autoruns) for persistence.",
        ],
        "tools": ["VirusTotal", "Autoruns", "Process Explorer", "Sigcheck (Sysinternals)"],
    },

    "PARENT_ANOMALY": {
        "description": "A critical Windows system process has an unexpected parent. "
                       "Malware often spawns or injects into system processes to hide.",
        "urgency": "HIGH",
        "mitre": ["T1055 - Process Injection", "T1134 - Access Token Manipulation"],
        "steps": [
            "1. Open Process Explorer (Sysinternals) and inspect the full process tree.",
            "2. Identify the anomalous parent process — check its path and signature.",
            "3. Hash and check the parent on VirusTotal.",
            "4. Check if the parent has any open network connections (netstat -ano).",
            "5. If the parent is malicious, terminate it: taskkill /PID <pid> /F",
            "6. Search for the malicious executable and delete it.",
            "7. Run Autoruns to find and remove any persistence mechanisms.",
            "8. Consider taking a memory dump before terminating.",
        ],
        "tools": ["Process Explorer", "Process Monitor", "Autoruns", "VirusTotal"],
    },

    "TEMP_EXECUTION": {
        "description": "An executable is running from a temporary or user-writable directory. "
                       "Legitimate software rarely runs persistently from %TEMP%.",
        "urgency": "HIGH",
        "mitre": ["T1204.002 - User Execution: Malicious File", "T1059 - Command and Scripting Interpreter"],
        "steps": [
            "1. Identify the full path of the executable from the scanner output.",
            "2. Hash the file: certutil -hashfile <path> SHA256",
            "3. Check hash on VirusTotal.",
            "4. Inspect the file with a hex editor or PE viewer (PEiD, CFF Explorer).",
            "5. Check if the file was recently created: dir /T:C <path>",
            "6. Terminate the process if malicious: taskkill /PID <pid> /F",
            "7. Delete the file.",
            "8. Run Autoruns to check for persistence entries pointing to temp dirs.",
            "9. Check browser downloads folder and email attachments for the infection vector.",
        ],
        "tools": ["VirusTotal", "CFF Explorer", "Autoruns", "Everything (file search)"],
    },

    "DLL_INJECTION": {
        "description": "A DLL loaded by a process was found in a suspicious location "
                       "(temp dir, AppData, Downloads). Indicates DLL injection or sideloading.",
        "urgency": "HIGH",
        "mitre": ["T1055.001 - Process Injection: DLL Injection",
                  "T1574.002 - Hijack Execution Flow: DLL Side-Loading"],
        "steps": [
            "1. Identify which process loaded the suspicious DLL and the DLL path.",
            "2. Hash the DLL: certutil -hashfile <dll_path> SHA256",
            "3. Check on VirusTotal.",
            "4. Use Process Explorer to view all DLLs loaded by the suspect process.",
            "5. Check if the DLL is a renamed or modified copy of a system DLL.",
            "6. Verify the DLL's digital signature (Sigcheck).",
            "7. If malicious: terminate the process, then delete the DLL.",
            "8. Search the system for other copies: where /R C:\\ <dll_name>",
            "9. Investigate how the DLL was placed (dropper, download, email attachment).",
        ],
        "tools": ["Process Explorer", "Sigcheck", "VirusTotal", "API Monitor"],
    },

    "DRIVER_HIDDEN": {
        "description": "A kernel driver is visible in one enumeration source but missing from another. "
                       "Hidden drivers are a hallmark of sophisticated rootkits.",
        "urgency": "IMMEDIATE",
        "mitre": ["T1014 - Rootkit", "T1215 - Kernel Modules and Extensions"],
        "steps": [
            "1. CRITICAL: Take a memory dump immediately before any other action.",
            "2. Run Volatility3 'windows.modules' and 'windows.modscan' — compare results.",
            "3. Note the driver's base address and compare with known drivers.",
            "4. Use WinDbg with kernel debugging to inspect the driver object.",
            "5. Check if the driver modifies SSDT, IDT, or IRP dispatch tables.",
            "6. Do NOT attempt to unload the driver manually — it may trigger system instability.",
            "7. Boot into a clean WinPE environment to inspect the driver file on disk.",
            "8. Hash and check the driver file on VirusTotal.",
            "9. Full system reimaging is recommended if a kernel rootkit is confirmed.",
        ],
        "tools": ["DumpIt.exe", "Volatility3", "WinDbg", "OSR Driver Loader", "Autoruns"],
    },

    "DRIVER_SUSPICIOUS": {
        "description": "A kernel driver was found outside of standard Windows driver directories, "
                       "or is unsigned / has an untrusted certificate.",
        "urgency": "HIGH",
        "mitre": ["T1014 - Rootkit", "T1553.006 - Subvert Trust Controls: Code Signing Policy"],
        "steps": [
            "1. Note the driver name and path from the scanner output.",
            "2. Check the driver's digital signature: Sigcheck -v <driver_path>",
            "3. Hash the driver: certutil -hashfile <path> SHA256",
            "4. Check hash on VirusTotal.",
            "5. Identify the service entry: sc qc <service_name>",
            "6. If malicious, disable the service: sc config <service_name> start= disabled",
            "7. Reboot and then delete the driver file.",
            "8. Check the registry key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>",
            "9. Remove the registry entry if the driver is confirmed malicious.",
        ],
        "tools": ["Sigcheck", "VirusTotal", "Autoruns", "DriverView (NirSoft)"],
    },

    "NETWORK_HIDING": {
        "description": "A TCP listening port is visible in one network enumeration source "
                       "but absent from another. Socket-level hiding is a rootkit indicator.",
        "urgency": "IMMEDIATE",
        "mitre": ["T1014 - Rootkit", "T1049 - System Network Connections Discovery"],
        "steps": [
            "1. Note the hidden port number.",
            "2. Run 'netstat -ano' and 'Get-NetTCPConnection' (PowerShell) to cross-verify.",
            "3. Take a memory dump — the socket will be visible via Volatility3 netscan.",
            "4. Try to identify the owning process via: netstat -b -ano",
            "5. Check if any unexpected process is listening on that port.",
            "6. Use Wireshark to capture traffic on the port to understand the protocol.",
            "7. Block the port at the firewall: netsh advfirewall firewall add rule ...",
            "8. Isolate the machine from the network.",
            "9. Assume system compromise — begin incident response.",
        ],
        "tools": ["Wireshark", "TCPView (Sysinternals)", "DumpIt.exe", "Volatility3"],
    },

    "MALWARE_PORT": {
        "description": "A process has a network connection on a port commonly used by malware, "
                       "remote access tools, or command-and-control frameworks.",
        "urgency": "HIGH",
        "mitre": ["T1571 - Non-Standard Port", "T1095 - Non-Application Layer Protocol",
                  "T1572 - Protocol Tunneling"],
        "steps": [
            "1. Identify the process and remote address from the scanner output.",
            "2. Check if the remote IP is known malicious: use VirusTotal, AbuseIPDB, or Shodan.",
            "3. Block outbound traffic to the remote IP at the firewall immediately.",
            "4. Capture network traffic to the remote endpoint with Wireshark.",
            "5. Hash and check the process executable on VirusTotal.",
            "6. Check the process's import table for suspicious APIs (WSAConnect, InternetOpen).",
            "7. Terminate the process if malicious.",
            "8. Check Autoruns for persistence of this process.",
            "9. Review DNS history for C2 domain lookups.",
            "10. Report the C2 IP/domain to your CIRT / threat intel team.",
        ],
        "tools": ["Wireshark", "VirusTotal", "AbuseIPDB", "Autoruns", "Process Monitor"],
    },

    "ORPHAN_SOCKET": {
        "description": "A network socket exists with no identifiable owning process. "
                       "This can indicate a rootkit hiding the owning process from the OS.",
        "urgency": "MEDIUM",
        "mitre": ["T1014 - Rootkit", "T1049 - System Network Connections Discovery"],
        "steps": [
            "1. Note the port number of the orphan socket.",
            "2. Attempt to find the process using: netstat -b -ano | findstr <port>",
            "3. Try Get-NetTCPConnection in PowerShell to see if ownership is visible.",
            "4. Take a memory dump and use Volatility3 netscan to identify the socket owner.",
            "5. If a hidden process is found, treat as PROCESS_HIDING.",
            "6. Block the port at the firewall as a precaution.",
            "7. Monitor the port with Wireshark for incoming/outgoing traffic.",
        ],
        "tools": ["TCPView", "Volatility3", "Wireshark", "Sysinternals Suite"],
    },

    "REGISTRY_PERSISTENCE": {
        "description": "A suspicious executable was found in a Windows Run or RunOnce registry key. "
                       "This is one of the most common persistence mechanisms used by malware.",
        "urgency": "HIGH",
        "mitre": ["T1547.001 - Registry Run Keys / Startup Folder"],
        "steps": [
            "1. Open the registry key shown in the scanner output (regedit.exe).",
            "2. Note the value name and data (path to the executable).",
            "3. Hash the executable: certutil -hashfile <path> SHA256",
            "4. Check hash on VirusTotal.",
            "5. Delete the registry value if malicious: reg delete <key> /v <value_name> /f",
            "6. Delete the executable file if malicious.",
            "7. Run Autoruns to check for additional persistence locations.",
            "8. Run a full antivirus scan.",
            "9. Check scheduled tasks: schtasks /query /fo LIST /v | more",
            "10. Check services: sc query | more",
        ],
        "tools": ["regedit.exe", "Autoruns", "VirusTotal", "Malwarebytes"],
    },

    "REGISTRY_WINLOGON": {
        "description": "The Winlogon registry key has been modified to load an unexpected DLL or executable. "
                       "This gives malware SYSTEM-level execution at every login.",
        "urgency": "IMMEDIATE",
        "mitre": ["T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL"],
        "steps": [
            "1. Open: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "2. Check 'Userinit' value — should be: C:\\Windows\\system32\\userinit.exe,",
            "3. Check 'Shell' value — should be: explorer.exe",
            "4. Check 'Notify' value — should be empty or absent on modern Windows.",
            "5. Hash any unexpected DLLs/executables in those values.",
            "6. Restore the correct values:",
            "   reg add 'HKLM\\...\\Winlogon' /v Userinit /d 'C:\\Windows\\system32\\userinit.exe,'",
            "7. Delete the malicious DLL/executable.",
            "8. Reboot and verify the values have not been restored by a rootkit.",
            "9. If values are restored after reboot, assume active kernel-level rootkit.",
        ],
        "tools": ["regedit.exe", "Autoruns", "Sigcheck", "Process Explorer"],
    },

    "REGISTRY_IFEO": {
        "description": "An Image File Execution Options (IFEO) Debugger key was found for a non-debug context. "
                       "Malware abuses this to silently replace or wrap any target executable.",
        "urgency": "HIGH",
        "mitre": ["T1546.012 - Event Triggered Execution: Image File Execution Options Injection"],
        "steps": [
            "1. Open: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
            "2. Find the key for the target executable (e.g., taskmgr.exe, regedit.exe).",
            "3. Check the 'Debugger' value — this is the malware's path.",
            "4. Hash and check the Debugger path on VirusTotal.",
            "5. Delete the malicious 'Debugger' value: reg delete <key> /v Debugger /f",
            "6. Or delete the entire key if it has no legitimate purpose.",
            "7. Verify the target executable is unmodified (check its hash).",
            "8. Check if the malware executable persists elsewhere (Run keys, services).",
        ],
        "tools": ["regedit.exe", "Autoruns", "VirusTotal", "Sigcheck"],
    },

    "MEMORY_INJECTION": {
        "description": "Memory analysis found executable code in a region that should not be executable, "
                       "or a process has injected memory with unusual permissions (PAGE_EXECUTE_READWRITE).",
        "urgency": "IMMEDIATE",
        "mitre": ["T1055 - Process Injection", "T1055.012 - Process Hollowing",
                  "T1055.002 - Portable Executable Injection"],
        "steps": [
            "1. Note the process name, PID, and memory address from the scanner output.",
            "2. Take a memory dump NOW if not already done.",
            "3. In Volatility3, run 'windows.malfind' against the specific PID.",
            "4. Dump the injected memory region: vol -f dump.raw windows.memmap --pid <pid> --dump",
            "5. Analyze the dumped shellcode with a disassembler (Ghidra, IDA Free).",
            "6. Check for signs of process hollowing: inspect the PE header at the injected address.",
            "7. Hash the host process executable and check on VirusTotal.",
            "8. Terminate the process.",
            "9. Full incident response — assume lateral movement may have occurred.",
        ],
        "tools": ["DumpIt.exe", "Volatility3", "Ghidra", "x64dbg", "PE-bear"],
    },

    "KERNEL_HOOK": {
        "description": "A hook was detected in the System Service Descriptor Table (SSDT) or "
                       "an IRP dispatch routine, pointing to non-standard kernel code. "
                       "This is a strong indicator of a kernel-mode rootkit.",
        "urgency": "IMMEDIATE",
        "mitre": ["T1014 - Rootkit", "T1562.001 - Impair Defenses: Disable or Modify Tools"],
        "steps": [
            "1. CRITICAL: Do NOT reboot — collect all volatile evidence first.",
            "2. Take a full memory dump with DumpIt.exe.",
            "3. Run Volatility3 'windows.ssdt' to enumerate all SSDT entries.",
            "4. Identify which kernel module owns the hooked function.",
            "5. Hash that kernel module file and check on VirusTotal.",
            "6. Kernel hooks cannot be safely removed at runtime — reimaging is required.",
            "7. Preserve disk image (use dd or FTK Imager) for forensic analysis.",
            "8. Boot from a clean WinPE USB to examine driver files without executing them.",
            "9. Report to your CIRT — this is likely nation-state or sophisticated malware.",
            "10. Full system reimaging is mandatory.",
        ],
        "tools": ["DumpIt.exe", "Volatility3", "WinDbg", "FTK Imager", "Rekall"],
    },

    "BENIGN": {
        "description": "This finding is likely a false positive or a known-good system behavior. "
                       "No immediate action required, but verify to be certain.",
        "urgency": "LOW",
        "mitre": [],
        "steps": [
            "1. Review the specific finding details carefully.",
            "2. Verify the process/driver is a known legitimate application.",
            "3. Check the digital signature of the file.",
            "4. If this is a recurring false positive, add it to the ignore list:",
            "   python main.py --ignore-process <name>",
            "   python main.py --ignore-port <port>",
            "   python main.py --ignore-driver <name>",
            "5. No further action needed if confirmed benign.",
        ],
        "tools": ["Sigcheck", "VirusTotal (for verification)"],
    },
}


def get_remediation(category: str) -> dict:
    return REMEDIATIONS.get(category, REMEDIATIONS["BENIGN"])
