#!/usr/bin/env python3
"""Port scanner with service detection, risk analysis and reports.
Use ONLY on systems you own or have written permission to test."""
import argparse
import asyncio
import logging
import socket
import sys
import time
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from scanner.core import scan_ports
from scanner.report import build_summary_text, write_html, write_json, write_summary
from scanner.risk import SEVERITY_ORDER, analyze, overall_rating, risk_score
from scanner.services import (HTTP_PORTS, HTTPS_WEB_PORTS, TLS_PORTS, extract_software,
                              grab_banner, identify_service)
from scanner.tls_http import check_http, check_tls
from scanner.utils import (compress_ports, folder_timestamp, is_private_or_local,
                           normalize_target, resolve_target, safe_name, validate_port_range)

TOOL_VERSION = "1.0.0"


def parse_args():
    p = argparse.ArgumentParser(description="Async TCP port scanner with risk analysis.")
    p.add_argument("target", nargs="?", help="IP address, domain or URL")
    p.add_argument("start_port", nargs="?", type=int)
    p.add_argument("end_port", nargs="?", type=int)
    p.add_argument("--timeout", type=float, default=2.0, help="seconds per connection attempt (default 2.0)")
    p.add_argument("--retries", type=int, default=1, help="extra attempts before calling a port filtered")
    p.add_argument("--concurrency", type=int, default=200, help="simultaneous connections (default 200)")
    p.add_argument("--output-dir", default="scans")
    p.add_argument("--open-only", action="store_true",
                   help="show only open ports in the terminal (all ports are still saved to the log)")
    p.add_argument("--yes", action="store_true", help="skip the prompt (you confirm you are authorized)")
    return p.parse_args()


def ask_int(prompt):
    while True:
        try:
            return int(input(prompt).strip())
        except ValueError:
            print("Please enter a number.")


def setup_logging(log_path):
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter("%(message)s"))

    log = logging.getLogger("portscanner")                 # terminal + file
    log.setLevel(logging.INFO)
    log.handlers.clear()
    log.addHandler(fh)
    log.addHandler(ch)

    file_log = logging.getLogger("portscanner.fileonly")   # file only
    file_log.setLevel(logging.INFO)
    file_log.handlers.clear()
    file_log.addHandler(fh)
    file_log.propagate = False
    return log, file_log


def confirm_authorization(host, ip, assume_yes):
    kind = "private/local address" if is_private_or_local(ip) else "PUBLIC address"
    print(f"\nTarget {host} resolves to {ip} ({kind}).")
    if assume_yes:
        return True
    answer = input('Type YES to confirm you own this target or have written permission to scan it: ')
    return answer.strip() == "YES"


async def enrich_port(res, ip, hostname, timeout, sem, log):
    async with sem:
        res.banner = await grab_banner(ip, res.port, timeout, hostname)
        res.service = identify_service(res.port, res.banner)
        res.software = extract_software(res.service, res.banner)
        tls_ok = False
        if res.port in TLS_PORTS:
            res.tls = await check_tls(ip, res.port, hostname, timeout)
            tls_ok = not res.tls.get("error")
        if res.port in HTTPS_WEB_PORTS and tls_ok:
            res.http = await check_http(ip, res.port, hostname, True, timeout)
        elif res.port in HTTP_PORTS or res.service == "http":
            res.http = await check_http(ip, res.port, hostname, False, timeout)
        if res.http and res.http.get("server"):
            res.software = res.http["server"]
        log.info("Port %d open | service=%s | software=%s", res.port, res.service, res.software or "-")


async def run(args, ip, hostname, log, file_log):
    log.info("Scanning %d ports...", args.end_port - args.start_port + 1)

    def on_result(r):
        label = {"open": "OPEN    ", "closed": "CLOSED  ", "filtered": "FILTERED"}[r.state]
        ms = f" | {r.response_ms} ms" if r.response_ms is not None else ""
        line = f"[{label}] port {r.port:<5} | {r.reason}{ms}"
        if args.open_only and r.state != "open":
            file_log.info(line)
        else:
            log.info(line)

    results = await scan_ports(ip, args.start_port, args.end_port, args.timeout,
                               args.retries, args.concurrency, on_result)
    open_results = [r for r in results if r.state == "open"]
    log.info("Port scan finished: %d open. Identifying services and running checks...", len(open_results))
    sem = asyncio.Semaphore(20)
    await asyncio.gather(*(enrich_port(r, ip, hostname, args.timeout, sem, log) for r in open_results))
    return results


def main() -> int:
    args = parse_args()
    try:
        host = normalize_target(args.target or input("Enter target (IP address or URL): "))
        if args.start_port is None:
            args.start_port = ask_int("Start port: ")
        if args.end_port is None:
            args.end_port = ask_int("End port: ")
        validate_port_range(args.start_port, args.end_port)
    except ValueError as exc:
        print(f"Input error: {exc}")
        return 1

    try:
        ip, is_ip = resolve_target(host)
    except socket.gaierror:
        print(f"Could not resolve '{host}' to an IPv4 address.")
        return 1
    hostname = None if is_ip else host

    if not confirm_authorization(host, ip, args.yes):
        print("Scan cancelled.")
        return 0

    run_dir = Path(args.output_dir) / safe_name(host) / folder_timestamp()
    run_dir.mkdir(parents=True, exist_ok=True)
    log, file_log = setup_logging(run_dir / "scan.log")
    log.info("Scan started: target=%s ip=%s ports=%d-%d", host, ip, args.start_port, args.end_port)

    started = datetime.now()
    t0 = time.perf_counter()
    try:
        results = asyncio.run(run(args, ip, hostname, log, file_log))
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        return 130
    duration = round(time.perf_counter() - t0, 2)

    open_results = [r for r in results if r.state == "open"]
    closed = [r.port for r in results if r.state == "closed"]
    filtered = [r.port for r in results if r.state == "filtered"]
    findings = analyze(open_results)
    counts = Counter(f.severity for f in findings)

    data = {
        "meta": {"tool_version": TOOL_VERSION, "target_input": host, "resolved_ip": ip,
                 "start_port": args.start_port, "end_port": args.end_port,
                 "started": started.strftime("%Y-%m-%d %H:%M:%S"), "duration_seconds": duration,
                 "timeout": args.timeout, "retries": args.retries, "concurrency": args.concurrency},
        "summary": {"total_scanned": len(results), "open": len(open_results),
                    "closed": len(closed), "filtered": len(filtered),
                    "closed_ranges": compress_ports(closed), "filtered_ranges": compress_ports(filtered),
                    "overall_risk": overall_rating(findings), "risk_score": risk_score(findings),
                    "findings_by_severity": {sev: counts.get(sev, 0) for sev in SEVERITY_ORDER}},
        "open_ports": [asdict(r) for r in open_results],
        "findings": [asdict(f) for f in findings],
    }

    write_json(run_dir / "report.json", data)
    write_summary(run_dir / "summary.txt", data)
    write_html(run_dir / "report.html", data)
    log.info("Reports saved in: %s", run_dir.resolve())
    file_log.info("\n" + build_summary_text(data))

    print("\n" + build_summary_text(data))
    print(f"\nFiles saved in: {run_dir.resolve()}")
    return 0
if __name__ == "__main__":
    sys.exit(main())