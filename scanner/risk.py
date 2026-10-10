"""Risk rules: turn scan results into findings with severity and advice."""
import re
from dataclasses import dataclass

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_POINTS = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}


@dataclass
class Finding:
    severity: str
    title: str
    port: int
    description: str
    recommendation: str
    confidence: str      # Confirmed | Likely | Potential


# port: (title, severity, description, recommendation)
PORT_RULES = {
    21: ("FTP service exposed", "High", "FTP sends usernames and passwords in clear text.",
         "Disable FTP or replace it with SFTP/FTPS. Restrict access by firewall."),
    22: ("SSH service exposed", "Low", "SSH is reachable and is a common brute-force target.",
         "Use key-based authentication, disable root login, and restrict source IPs."),
    23: ("Telnet service exposed", "Critical", "Telnet is unencrypted and obsolete.",
         "Disable Telnet and use SSH instead."),
    69: ("TFTP service exposed", "High", "TFTP has no authentication.", "Disable it or restrict it to trusted hosts."),
    80: ("Unencrypted HTTP service", "Low", "Traffic on this port is not encrypted.",
         "Redirect HTTP to HTTPS and enable HSTS."),
    110: ("POP3 (cleartext) exposed", "Medium", "POP3 without TLS exposes credentials.", "Use POP3S (995) or disable."),
    111: ("RPC portmapper exposed", "Medium", "rpcbind can reveal internal services.", "Block from untrusted networks."),
    135: ("Windows RPC (MSRPC) exposed", "High", "MSRPC is frequently abused for lateral movement.",
          "Block at the perimeter; allow only from internal hosts."),
    139: ("NetBIOS session service exposed", "High", "NetBIOS leaks host information and enables relay attacks.",
          "Disable NetBIOS over TCP/IP where not needed; block externally."),
    143: ("IMAP (cleartext) exposed", "Medium", "IMAP without TLS exposes credentials.", "Use IMAPS (993)."),
    389: ("LDAP exposed", "Medium", "LDAP can leak directory data and is unencrypted by default.",
          "Use LDAPS and restrict access."),
    445: ("SMB service exposed", "High", "SMB has a long history of serious vulnerabilities and worm outbreaks.",
          "Never expose SMB to untrusted networks; patch and restrict by firewall."),
    512: ("rexec service exposed", "High", "Legacy r-service with weak authentication.", "Disable it."),
    513: ("rlogin service exposed", "High", "Legacy r-service with weak authentication.", "Disable it."),
    514: ("rsh service exposed", "High", "Legacy r-service with weak authentication.", "Disable it."),
    1433: ("Microsoft SQL Server exposed", "High", "Databases should not be reachable from untrusted networks.",
           "Restrict by firewall/VPN and enforce strong authentication."),
    1521: ("Oracle database exposed", "High", "Databases should not be reachable from untrusted networks.",
           "Restrict by firewall/VPN."),
    2049: ("NFS exposed", "High", "NFS shares may be readable without strong authentication.",
           "Restrict exports to specific hosts."),
    2375: ("Docker API exposed (unencrypted)", "Critical",
           "An unauthenticated Docker API usually allows full host takeover.",
           "Disable remote API or protect it with TLS client certificates."),
    3306: ("MySQL/MariaDB exposed", "High", "Databases should not be reachable from untrusted networks.",
           "Bind to localhost or restrict by firewall/VPN."),
    3389: ("RDP exposed", "High", "RDP is a top target for brute force and ransomware access.",
           "Put RDP behind a VPN, enable NLA and MFA, and restrict source IPs."),
    5432: ("PostgreSQL exposed", "High", "Databases should not be reachable from untrusted networks.",
           "Restrict by firewall/VPN."),
    5900: ("VNC exposed", "High", "VNC often has weak or no authentication and weak encryption.",
           "Tunnel via VPN/SSH and enforce strong passwords."),
    5985: ("WinRM (HTTP) exposed", "Medium", "Remote management interface reachable.", "Restrict to management hosts."),
    6379: ("Redis exposed", "High", "Redis is often deployed without authentication.",
           "Bind to localhost, set a password, restrict by firewall."),
    9200: ("Elasticsearch exposed", "High", "Often deployed without authentication, leaking data.",
           "Enable authentication and restrict access."),
    11211: ("Memcached exposed", "High", "No authentication by default; abused for data leaks and amplification.",
            "Bind to localhost or restrict by firewall."),
    27017: ("MongoDB exposed", "High", "Often deployed without authentication.",
            "Enable authentication and restrict access."),
}


def analyze(open_results) -> list:
    findings = []
    for r in open_results:
        def add(sev, title, desc, fix, conf="Confirmed", _r=r):
            findings.append(Finding(sev, title, _r.port, desc, fix, conf))

        rule = PORT_RULES.get(r.port)
        if rule:
            title, sev, desc, fix = rule
            conf = "Confirmed" if r.banner else "Likely"
            add(sev, title, f"{desc} (Port {r.port} is open; service type is based on "
                f"{'the banner' if r.banner else 'the port number'}.)", fix, conf)

        _software_findings(r, add)
        _tls_findings(r, add)
        _http_findings(r, add)

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.port))
    return findings


def _software_findings(r, add):
    sw = r.software or ""
    if r.banner.startswith("SSH-1.") and not r.banner.startswith("SSH-1.99"):
        add("High", "SSH protocol version 1 in use", "SSH-1 has known cryptographic weaknesses.",
            "Disable SSH protocol 1.")
    m = re.search(r"OpenSSH[_-](\d+)\.", sw)
    if m and int(m.group(1)) < 7:
        add("Medium", "Potentially outdated OpenSSH", f"Banner shows '{sw}'. Versions before 7.0 are very old.",
            "Verify the real version and update.", "Potential")
    if "vsftpd 2.3.4" in sw.lower():
        add("Critical", "vsFTPd 2.3.4 banner (known backdoored release)",
            "This exact release was distributed with a backdoor (CVE-2011-2523). Banner match only.",
            "Verify and replace immediately.", "Potential")
    if re.search(r"Apache/2\.[02]\.", sw):
        add("Medium", "End-of-life Apache version", f"Banner shows '{sw}'. Apache 2.0/2.2 is end-of-life.",
            "Upgrade to a supported version.", "Potential")
    m = re.search(r"Microsoft-IIS/(\d+)\.", sw)
    if m and int(m.group(1)) < 8:
        add("Medium", "End-of-life IIS version", f"Banner shows '{sw}'. This IIS version is end-of-life.",
            "Upgrade the OS and IIS.", "Potential")
    m = re.search(r"PHP/(\d+)\.", (r.http or {}).get("x_powered_by", ""))
    if m and int(m.group(1)) < 8:
        add("Medium", "End-of-life PHP version", "X-Powered-By shows a PHP version that no longer gets security fixes.",
            "Upgrade PHP.", "Potential")


def _tls_findings(r, add):
    t = r.tls or {}
    if not t or t.get("error"):
        return
    if t.get("cert_valid") is False:
        err = t.get("cert_error", "")
        low = err.lower()
        if "expired" in low:
            add("High", "TLS certificate expired", f"Verification error: {err}", "Renew the certificate.")
        elif "self" in low and "signed" in low:
            add("Medium", "Self-signed TLS certificate", f"Verification error: {err}",
                "Use a certificate from a trusted CA.")
        elif "hostname" in low or "match" in low:
            add("Medium", "TLS certificate name mismatch", f"Verification error: {err}",
                "Issue a certificate that covers this hostname.")
        else:
            add("Medium", "TLS certificate not trusted", f"Verification error: {err}",
                "Check the certificate chain and issuer.")
    elif t.get("days_left") is not None and t["days_left"] < 30:
        add("Low", "TLS certificate expires soon", f"Certificate expires in {t['days_left']} day(s).",
            "Renew before expiry.")
    legacy = list(t.get("legacy_protocols", []))
    if t.get("tls_version") in ("TLSv1", "TLSv1.1", "SSLv3") and t["tls_version"] not in legacy:
        legacy.append(t["tls_version"])
    if legacy:
        add("Medium", "Deprecated TLS versions accepted", f"Server accepted: {', '.join(legacy)}.",
            "Allow only TLS 1.2 and 1.3.")


def _http_findings(r, add):
    h = r.http or {}
    if not h or h.get("error"):
        return
    if h.get("server") and re.search(r"\d", h["server"]):
        add("Low", "Web server version disclosed", f"Server header reveals '{h['server']}'.",
            "Hide version details in the server config.")
    if h.get("x_powered_by"):
        add("Low", "Technology disclosed (X-Powered-By)", f"Header reveals '{h['x_powered_by']}'.",
            "Remove the X-Powered-By header.")
    if h.get("missing_headers"):
        add("Low", "Missing HTTP security headers", "Missing: " + ", ".join(h["missing_headers"]) + ".",
            "Add the recommended security headers.")
    for sp in h.get("sensitive_paths", []):
        add(sp["severity"], sp["description"], f"{sp['path']} returned HTTP 200 with matching content.",
            "Remove or restrict access to this resource.")


def overall_rating(findings) -> str:
    for sev in SEVERITY_ORDER[:-1]:
        if any(f.severity == sev for f in findings):
            return sev
    return "None"


def risk_score(findings) -> int:
    return min(100, sum(SEVERITY_POINTS[f.severity] for f in findings))