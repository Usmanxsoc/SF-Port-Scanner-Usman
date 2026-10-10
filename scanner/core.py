"""Async TCP connect scanner. Classifies each port as open, closed or filtered."""
import asyncio
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class PortResult:
    port: int
    state: str                      # open | closed | filtered
    reason: str
    response_ms: Optional[float] = None
    service: str = "unknown"
    banner: str = ""
    software: str = ""
    tls: Optional[dict] = None
    http: Optional[dict] = None


async def probe_port(ip: str, port: int, timeout: float, retries: int) -> PortResult:
    reason = "No response (timeout)"
    for _ in range(retries + 1):
        start = time.perf_counter()
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        except (ConnectionRefusedError, ConnectionResetError):
            return PortResult(port, "closed", "Connection refused (host answered with reset)")
        except (asyncio.TimeoutError, TimeoutError):
            reason = "No response (timeout)"
            continue
        except OSError as exc:
            reason = f"Network error: {exc.strerror or exc}"
            continue
        else:
            elapsed = (time.perf_counter() - start) * 1000
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return PortResult(port, "open", "TCP handshake completed", round(elapsed, 1))
    return PortResult(port, "filtered", f"{reason} after {retries + 1} attempt(s)")


async def scan_ports(ip, start, end, timeout, retries, concurrency, on_result=None):
    sem = asyncio.Semaphore(concurrency)

    async def worker(port):
        async with sem:
            result = await probe_port(ip, port, timeout, retries)
        if on_result:
            on_result(result)
        return result

    results = await asyncio.gather(*(worker(p) for p in range(start, end + 1)))
    return sorted(results, key=lambda r: r.port)