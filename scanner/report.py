"""Report writers: JSON, plain-text summary, HTML."""
import html
import json
from pathlib import Path

from .risk import SEVERITY_ORDER

SEV_COLORS = {"Critical": "#b91c1c", "High": "#ea580c", "Medium": "#ca8a04",
              "Low": "#2563eb", "Info": "#6b7280", "None": "#16a34a"}


def write_json(path, data) -> None:
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def build_summary_text(data) -> str:
    m, s = data["meta"], data["summary"]
    lines = ["=" * 66, "PORT SCAN SUMMARY", "=" * 66,
             f"Target        : {m['target_input']} ({m['resolved_ip']})",
             f"Port range    : {m['start_port']}-{m['end_port']}",
             f"Started       : {m['started']}",
             f"Duration      : {m['duration_seconds']} s",
             f"Scanned       : {s['total_scanned']} ports",
             f"Open          : {s['open']}",
             f"Closed        : {s['closed']}",
             f"Filtered      : {s['filtered']} (no response)",
             f"Overall risk  : {s['overall_risk']}  (score {s['risk_score']}/100)",
             "-" * 66, "OPEN PORTS"]
    if data["open_ports"]:
        lines.append(f"{'PORT':<8}{'SERVICE':<16}SOFTWARE")
        for p in data["open_ports"]:
            lines.append(f"{p['port']:<8}{p['service']:<16}{(p['software'] or '-')[:40]}")
    else:
        lines.append("No open ports found.")
    lines += ["-" * 66, "FINDINGS"]
    if data["findings"]:
        for f in data["findings"]:
            lines.append(f"[{f['severity'].upper()}] {f['title']} (port {f['port']}, {f['confidence']})")
            lines.append(f"    Why : {f['description']}")
            lines.append(f"    Fix : {f['recommendation']}")
    else:
        lines.append("No findings.")
    lines += ["-" * 66,
              f"Closed ports   : {s['closed_ranges']}",
              f"Filtered ports : {s['filtered_ranges']}",
              "-" * 66,
              "Note: results reflect what was reachable from the machine that ran the scan.",
              "'Potential' findings are based on banners/versions and must be verified.",
              "=" * 66]
    return "\n".join(lines)


def write_summary(path, data) -> None:
    Path(path).write_text(build_summary_text(data), encoding="utf-8")


CSS = """
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f3f4f6;color:#111827}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
h1{margin:0 0 4px}h2{margin-top:32px;border-bottom:2px solid #e5e7eb;padding-bottom:6px}
.sub{color:#6b7280;margin-bottom:20px}
.cards{display:flex;gap:12px;flex-wrap:wrap}
.card{background:#fff;border-radius:10px;padding:14px 20px;min-width:110px;text-align:center;box-shadow:0 1px 3px #0002}
.num{font-size:28px;font-weight:700}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px #0002}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #e5e7eb;font-size:14px;vertical-align:top}
th{background:#111827;color:#fff}
.badge{color:#fff;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600}
.finding{background:#fff;border-radius:10px;padding:12px 16px;margin:10px 0;box-shadow:0 1px 3px #0002}
.muted{color:#6b7280;font-size:13px}
"""


def _badge(sev):
    return f'<span class="badge" style="background:{SEV_COLORS.get(sev, "#6b7280")}">{html.escape(sev)}</span>'


def _clean(text, limit=120):
    return html.escape((text or "-").replace("\r", " ").replace("\n", " ")[:limit])


def write_html(path, data) -> None:
    m, s = data["meta"], data["summary"]
    esc = html.escape
    cards = "".join(
        f'<div class="card"><div class="num" style="color:{SEV_COLORS[sev]}">'
        f'{s["findings_by_severity"].get(sev, 0)}</div><div>{sev}</div></div>'
        for sev in SEVERITY_ORDER)
    port_rows = "".join(
        f'<tr><td>{p["port"]}</td><td>{esc(p["service"])}</td><td>{_clean(p["software"], 60)}</td>'
        f'<td>{_clean(p["banner"])}</td><td>{p["response_ms"]}</td></tr>'
        for p in data["open_ports"]) or '<tr><td colspan="5">No open ports found.</td></tr>'
    finding_blocks = "".join(
        f'<div class="finding">{_badge(f["severity"])} <b>{esc(f["title"])}</b> '
        f'<span class="muted">port {f["port"]} | {esc(f["confidence"])}</span>'
        f'<p>{esc(f["description"])}</p><p><b>Recommendation:</b> {esc(f["recommendation"])}</p></div>'
        for f in data["findings"]) or "<p>No findings.</p>"

    page = (
        '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Scan report</title><style>'
        + CSS + '</style></head><body><div class="wrap">'
        f'<h1>Port Scan Report</h1><div class="sub">{esc(m["target_input"])} ({esc(m["resolved_ip"])}) '
        f'| ports {m["start_port"]}-{m["end_port"]} | {esc(m["started"])} | {m["duration_seconds"]} s</div>'
        f'<div class="cards"><div class="card"><div class="num" style="color:{SEV_COLORS.get(s["overall_risk"], "#111")}">'
        f'{esc(s["overall_risk"])}</div><div>Overall risk ({s["risk_score"]}/100)</div></div>'
        f'<div class="card"><div class="num">{s["open"]}</div><div>Open</div></div>'
        f'<div class="card"><div class="num">{s["closed"]}</div><div>Closed</div></div>'
        f'<div class="card"><div class="num">{s["filtered"]}</div><div>Filtered</div></div></div>'
        '<h2>Findings by severity</h2><div class="cards">' + cards + '</div>'
        '<h2>Open ports</h2><table><tr><th>Port</th><th>Service</th><th>Software</th><th>Banner</th>'
        '<th>Response ms</th></tr>' + port_rows + '</table>'
        '<h2>Findings</h2>' + finding_blocks +
        '<h2>Other ports</h2>'
        f'<p><b>Closed:</b> {esc(s["closed_ranges"])}</p><p><b>Filtered (no response):</b> {esc(s["filtered_ranges"])}</p>'
        '<p class="muted">Results reflect what was reachable from the machine that ran the scan. '
        '"Potential" findings come from banners/versions and must be verified manually.</p>'
        '</div></body></html>')
    Path(path).write_text(page, encoding="utf-8")