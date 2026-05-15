"""
Network anomaly scanner.

Detection methods:
1. Cross-view: compare TCP LISTEN ports from psutil vs netstat -ano.
   A port visible in one source but not the other is a socket-hiding indicator.
2. Suspicious port check: connections on ports known to be used by malware/C2.
3. Orphan socket check: sockets with no owning process.
"""

import subprocess
import re
import logging
import psutil

log = logging.getLogger(__name__)

# Ports commonly abused by malware / C2 frameworks.
_SUSPICIOUS_PORTS = {
    1080, 4444, 4445, 5554, 6666, 7777, 8080, 8888,
    9001, 9050, 9150,   # Tor
    31337, 12345, 54321,
    2222, 6667, 6697,   # IRC
    1337, 1338,
}

# Known legitimate processes that happen to use ports in _SUSPICIOUS_PORTS.
# Format: {process_name_lower: {port, ...}}
_PORT_WHITELIST: dict[str, set[int]] = {
    "rzsdkserver.exe":  {1337},             # Razer Synapse SDK
    "tnslsnr.exe":      {8080, 1521, 1158}, # Oracle TNS Listener
    "fiddler.exe":      {8080, 8888},       # Fiddler web proxy
    "charles.exe":      {8080, 8888},       # Charles proxy
    "burpsuite.exe":    {8080, 8888},       # Burp Suite
    "python.exe":       {8080, 8888},       # Local dev servers
    "node.exe":         {8080, 8888},
    "java.exe":         {8080, 8888},
    "tor.exe":          {9050, 9150},       # Legitimate Tor client
}


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def _tcp_listen_ports_from_psutil() -> set[int]:
    ports = set()
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.status == "LISTEN" and c.laddr:
                ports.add(c.laddr.port)
    except Exception as exc:
        log.debug("psutil TCP listen query failed: %s", exc)
    return ports


def _tcp_listen_ports_from_netstat() -> set[int]:
    """Query both IPv4 (tcp) and IPv6 (tcpv6) listening ports from netstat."""
    ports = set()
    for proto in ("tcp", "tcpv6"):
        try:
            out = subprocess.check_output(
                ["netstat", "-ano", "-p", proto],
                stderr=subprocess.DEVNULL,
                timeout=30,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            for line in out.splitlines():
                m = re.search(r"(?:TCP|TCPV6)\s+\S+:(\d+)\s+\S+\s+LISTENING", line, re.I)
                if m:
                    ports.add(int(m.group(1)))
        except Exception as exc:
            log.debug("netstat -p %s failed: %s", proto, exc)
    return ports


def _all_connections_from_psutil() -> list[dict]:
    conns = []
    try:
        for c in psutil.net_connections(kind="all"):
            conns.append({
                "pid":    c.pid,
                "lport":  c.laddr.port if c.laddr else None,
                "raddr":  f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                "status": c.status,
                "family": c.family,
            })
    except Exception as exc:
        log.debug("psutil net_connections (all) failed: %s", exc)
    return conns


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def _cross_view_check(psutil_listen: set[int], netstat_listen: set[int]) -> list[dict]:
    """
    Compare TCP LISTEN ports. Skip the Windows dynamic/ephemeral range (49152-65535):
    those ports are allocated and released between the two queries, causing
    false positives with no security value.
    """
    findings = []
    for port in sorted(psutil_listen - netstat_listen):
        if 49152 <= port <= 65535:
            continue  # dynamic ephemeral range - timing artifact
        findings.append({
            "port":     port,
            "severity": "HIGH",
            "reason":   f"TCP port {port} LISTEN visible in psutil but absent from netstat - possible socket hook",
        })
    for port in sorted(netstat_listen - psutil_listen):
        if 49152 <= port <= 65535:
            continue
        findings.append({
            "port":     port,
            "severity": "HIGH",
            "reason":   f"TCP port {port} LISTEN visible in netstat but absent from psutil - possible kernel-level evasion",
        })
    return findings


def _suspicious_port_check(conns: list[dict]) -> list[dict]:
    seen: set[tuple] = set()   # deduplicate (pname, port)
    findings = []
    for c in conns:
        lport = c.get("lport")
        if not lport or lport not in _SUSPICIOUS_PORTS:
            continue
        try:
            pname = psutil.Process(c["pid"]).name() if c["pid"] else "<unknown>"
        except Exception:
            pname = "<unknown>"

        # Skip whitelisted process+port combinations.
        if lport in _PORT_WHITELIST.get(pname.lower(), set()):
            continue

        key = (pname.lower(), lport)
        if key in seen:
            continue
        seen.add(key)

        findings.append({
            "port":     lport,
            "pid":      c["pid"],
            "process":  pname,
            "severity": "MEDIUM",
            "reason":   f"Connection on known malware port {lport} owned by {pname} (PID {c['pid']})",
        })
    return findings


def _orphan_socket_check(conns: list[dict]) -> list[dict]:
    seen_ports: set[int] = set()
    findings = []
    for c in conns:
        if c["pid"] is None and c["lport"] and c["lport"] not in seen_ports:
            seen_ports.add(c["lport"])
            findings.append({
                "port":     c["lport"],
                "severity": "MEDIUM",
                "reason":   f"Socket on port {c['lport']} has no owning process (orphan socket)",
            })
    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def scan_network() -> list[dict]:
    psutil_listen  = _tcp_listen_ports_from_psutil()
    netstat_listen = _tcp_listen_ports_from_netstat()
    all_conns      = _all_connections_from_psutil()

    results = (
        _cross_view_check(psutil_listen, netstat_listen)
        + _suspicious_port_check(all_conns)
        + _orphan_socket_check(all_conns)
    )

    for r in results:
        log.warning("[%s] %s", r.get("severity"), r.get("reason"))

    return results
