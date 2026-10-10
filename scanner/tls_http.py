"""TLS certificate/protocol checks and basic HTTP security checks."""
import asyncio
import http.client
import secrets
import socket
import ssl
import time
import warnings


# ---------------------------- TLS ----------------------------
def _name(field) -> str:
    d = {k: v for rdn in field for k, v in rdn}
    return d.get("commonName") or d.get("organizationName") or ""


def _fill_cert(info: dict, cert: dict) -> None:
    info["subject"] = _name(cert.get("subject", ()))
    info["issuer"] = _name(cert.get("issuer", ()))
    not_after = cert.get("notAfter", "")
    info["not_after"] = not_after
    if not_after:
        info["days_left"] = int((ssl.cert_time_to_seconds(not_after) - time.time()) / 86400)


def _unverified_details(info: dict, ip: str, port: int, timeout: float) -> None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock) as s:
                info["tls_version"] = s.version() or ""
                cipher = s.cipher()
                info["cipher"] = cipher[0] if cipher else ""
    except (ssl.SSLError, OSError):
        pass


def _legacy_protocols(ip: str, port: int, timeout: float) -> list:
    """Try to connect using only TLS 1.0 / 1.1. If your local OpenSSL blocks
    these versions the test is inconclusive and nothing is reported."""
    found = []
    for name, version in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version
                try:
                    ctx.set_ciphers("ALL:@SECLEVEL=0")
                except ssl.SSLError:
                    pass
                with socket.create_connection((ip, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock):
                        found.append(name)
        except (ssl.SSLError, OSError, ValueError):
            continue
    return found


def _tls_check_sync(ip, port, hostname, timeout) -> dict:
    info = {"tls_version": "", "cipher": "", "cert_valid": None, "cert_error": "",
            "subject": "", "issuer": "", "not_after": "", "days_left": None,
            "legacy_protocols": [], "error": ""}
    ctx = ssl.create_default_context()
    if not hostname:                      # IP input: hostname matching is not possible
        ctx.check_hostname = False
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as s:
                info["tls_version"] = s.version() or ""
                cipher = s.cipher()
                info["cipher"] = cipher[0] if cipher else ""
                _fill_cert(info, s.getpeercert() or {})
                info["cert_valid"] = True
    except ssl.SSLCertVerificationError as exc:
        info["cert_valid"] = False
        info["cert_error"] = exc.verify_message or str(exc)
        _unverified_details(info, ip, port, timeout)
    except (ssl.SSLError, OSError) as exc:
        info["error"] = f"{type(exc).__name__}: {exc}"
        return info
    info["legacy_protocols"] = _legacy_protocols(ip, port, timeout)
    return info


async def check_tls(ip, port, hostname, timeout) -> dict:
    return await asyncio.to_thread(_tls_check_sync, ip, port, hostname, max(timeout, 3.0))


# ---------------------------- HTTP ----------------------------
SENSITIVE_PATHS = [
    ("/.git/HEAD", "Exposed Git repository", "High", lambda b: b.startswith(b"ref:")),
    ("/.env", "Exposed environment file", "Critical",
     lambda b: b"=" in b and b"<html" not in b.lower()),
    ("/phpmyadmin/", "phpMyAdmin panel reachable", "Medium", lambda b: b"phpmyadmin" in b.lower()),
    ("/server-status", "Apache server-status page reachable", "Medium",
     lambda b: b"apache server status" in b.lower()),
    ("/admin", "Admin path reachable (verify it requires authentication)", "Low", lambda b: True),
]


def _http_check_sync(ip, port, hostname, use_tls, timeout) -> dict:
    info = {"scheme": "https" if use_tls else "http", "status": None, "server": "",
            "x_powered_by": "", "missing_headers": [], "sensitive_paths": [],
            "wildcard_200": False, "error": ""}
    connect_host = hostname or ip
    host_header = hostname or ip
    ctx = None
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    def fetch(path):
        if use_tls:
            conn = http.client.HTTPSConnection(connect_host, port=port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(connect_host, port=port, timeout=timeout)
        try:
            conn.request("GET", path, headers={"Host": host_header,
                                               "User-Agent": "PortScanner/1.0",
                                               "Connection": "close"})
            resp = conn.getresponse()
            body = resp.read(2048)
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, body
        finally:
            conn.close()

    try:
        status, headers, _ = fetch("/")
    except Exception as exc:
        info["error"] = f"{type(exc).__name__}: {exc}"
        return info

    info["status"] = status
    info["server"] = headers.get("server", "")
    info["x_powered_by"] = headers.get("x-powered-by", "")

    required = {"x-content-type-options": "X-Content-Type-Options",
                "content-security-policy": "Content-Security-Policy",
                "referrer-policy": "Referrer-Policy"}
    if use_tls:
        required["strict-transport-security"] = "Strict-Transport-Security"
    info["missing_headers"] = [label for key, label in required.items() if key not in headers]
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        info["missing_headers"].append("X-Frame-Options (or CSP frame-ancestors)")

    # If a random non-existent path returns 200, the site answers 200 to everything
    # and path checks would produce false positives, so skip them.
    try:
        wildcard_status, _, _ = fetch("/not-a-real-page-" + secrets.token_hex(4))
    except Exception:
        wildcard_status = None
    if wildcard_status == 200:
        info["wildcard_200"] = True
        return info

    for path, description, severity, validator in SENSITIVE_PATHS:
        try:
            st, _, body = fetch(path)
        except Exception:
            continue
        if st == 200 and validator(body):
            info["sensitive_paths"].append({"path": path, "description": description,
                                            "severity": severity})
    return info


async def check_http(ip, port, hostname, use_tls, timeout) -> dict:
    return await asyncio.to_thread(_http_check_sync, ip, port, hostname, use_tls, max(timeout, 3.0))