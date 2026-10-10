"""Service identification and banner grabbing."""
import asyncio
import re

COMMON_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    512: "rexec", 513: "rlogin", 514: "rsh", 587: "smtp-submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker-api", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 5985: "winrm", 5986: "winrm-ssl", 6379: "redis",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}

TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}
HTTPS_WEB_PORTS = {443, 8443, 9443}
HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888}


async def grab_banner(ip, port, timeout=2.0, host=None) -> str:
    if port in TLS_PORTS:
        return ""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return ""
    data = b""
    try:
        if port in HTTP_PORTS:
            request = f"HEAD / HTTP/1.0\r\nHost: {host or ip}\r\nUser-Agent: PortScanner/1.0\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    text = data.decode("utf-8", errors="replace")
    text = "".join(ch if ch.isprintable() or ch in "\r\n" else "." for ch in text).strip()
    return text[:300]


def identify_service(port: int, banner: str) -> str:
    b = banner.lower()
    if banner.startswith("SSH-"):
        return "ssh"
    if banner.startswith("HTTP/"):
        return "http"
    if banner.startswith("220") and "ftp" in b:
        return "ftp"
    if banner.startswith("220") and "smtp" in b:
        return "smtp"
    if banner.startswith("+OK"):
        return "pop3"
    if banner.startswith("* OK"):
        return "imap"
    if banner.startswith("RFB "):
        return "vnc"
    if "mysql" in b or "mariadb" in b:
        return "mysql"
    return COMMON_SERVICES.get(port, "unknown")


def extract_software(service: str, banner: str) -> str:
    if not banner:
        return ""
    if banner.startswith("SSH-"):
        first = banner.splitlines()[0]
        parts = first.split("-", 2)
        return parts[2].strip() if len(parts) == 3 else first
    match = re.search(r"^Server:\s*(.+)$", banner, re.I | re.M)
    if match:
        return match.group(1).strip()
    if service == "ftp" and banner.startswith("220"):
        return banner.splitlines()[0][4:].strip()
    return ""