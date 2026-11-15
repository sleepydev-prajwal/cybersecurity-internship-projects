"""
Mini Vulnerability Scanner
Task 2 - scans open ports, checks HTTP security headers and server
version info, then writes a simple vulnerability report.

ONLY scan your own machine (127.0.0.1) or scanme.nmap.org
(a server that explicitly allows test scans). Scanning other
systems without permission is illegal.
"""

import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Common ports and what they usually are
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5000: "Flask/Dev", 8080: "HTTP-Alt",
}

# Ports that are risky if open to the internet
RISKY_PORTS = {
    21: "FTP sends data in plain text.",
    23: "Telnet is unencrypted, use SSH instead.",
    139: "NetBIOS can leak system info.",
    445: "SMB is a common ransomware target.",
    3306: "Database should not be exposed publicly.",
    3389: "RDP is a common brute-force target.",
}

# Security headers a good web server should send
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces HTTPS (protects against downgrade attacks).",
    "Content-Security-Policy": "Helps prevent XSS attacks.",
    "X-Frame-Options": "Protects against clickjacking.",
    "X-Content-Type-Options": "Stops MIME-type sniffing.",
}


def scan_port(host, port):
    """Try to connect to a port. If connection works, port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((host, port)) == 0:
                return port
    except OSError:
        pass
    return None


def scan_ports(host):
    with ThreadPoolExecutor(max_workers=50) as pool:
        results = pool.map(lambda p: scan_port(host, p), COMMON_PORTS)
    return [p for p in results if p is not None]


def check_http(host, use_https=False):
    """Fetch the homepage and return headers (or None if it fails)."""
    scheme = "https" if use_https else "http"
    try:
        req = urllib.request.Request(f"{scheme}://{host}", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return dict(resp.headers)
    except Exception:
        return None


def build_report(host, open_ports, headers):
    lines = []
    lines.append("=" * 50)
    lines.append("VULNERABILITY SCAN REPORT")
    lines.append(f"Target : {host}")
    lines.append(f"Time   : {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}")
    lines.append("=" * 50)

    # Section 1: ports
    lines.append("\n[1] OPEN PORTS")
    if open_ports:
        for p in open_ports:
            lines.append(f"  - Port {p} ({COMMON_PORTS[p]}) is OPEN")
            if p in RISKY_PORTS:
                lines.append(f"      RISK: {RISKY_PORTS[p]}")
    else:
        lines.append("  No common ports open.")

    # Section 2: headers and server version
    lines.append("\n[2] HTTP SECURITY HEADERS")
    if headers is None:
        lines.append("  Could not fetch web page (no web server or blocked).")
    else:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for name, why in SECURITY_HEADERS.items():
            if name.lower() in headers_lower:
                lines.append(f"  [OK]      {name}")
            else:
                lines.append(f"  [MISSING] {name} - {why}")

        lines.append("\n[3] SERVER INFORMATION")
        server = headers_lower.get("server")
        if server:
            lines.append(f"  Server banner: {server}")
            lines.append("  NOTE: Check this version for known vulnerabilities (CVE).")
            lines.append("        Exposing exact versions helps attackers.")
        else:
            lines.append("  Server version is hidden (good).")

    lines.append("\n" + "=" * 50)
    return "\n".join(lines)


if __name__ == "__main__":
    host = input("Enter target (127.0.0.1 or scanme.nmap.org): ").strip()
    print(f"\nScanning {host} ... please wait\n")

    open_ports = scan_ports(host)
    headers = check_http(host, use_https=(443 in open_ports and 80 not in open_ports))

    report = build_report(host, open_ports, headers)
    print(report)

    filename = f"scan_report_{host.replace('.', '_')}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\nReport saved as {filename}")
