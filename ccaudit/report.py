"""Console, JSON and HTML report writers."""
from __future__ import annotations

import datetime as dt
import html
import json

from .models import CheckResult, FrameworkResult, SEVERITY_RANK, Status


def _sorted_checks(results: dict[str, CheckResult]) -> list[CheckResult]:
    return sorted(results.values(), key=lambda r: (-SEVERITY_RANK[r.severity], r.check_id))


def to_dict(results: dict[str, CheckResult], frameworks: list[FrameworkResult],
            meta: dict | None = None) -> dict:
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "meta": meta or {},
        "frameworks": [{
            "id": f.framework_id, "name": f.name, "disclaimer": f.disclaimer,
            "score_percent": f.score, "passed": f.passed, "failed": f.failed,
            "not_applicable": f.not_applicable,
            "controls": [{
                "id": c.control_id, "title": c.title, "status": c.status.value,
                "checks": {k: v.value for k, v in c.check_statuses.items()},
            } for c in f.controls],
        } for f in frameworks],
        "checks": [{
            "id": r.check_id, "title": r.title, "severity": r.severity, "status": r.status.value,
            "description": r.description, "remediation": r.remediation,
            "findings": [{"resource": x.resource, "status": x.status.value, "detail": x.detail}
                         for x in r.findings],
        } for r in _sorted_checks(results)],
    }


def to_json(results, frameworks, meta=None) -> str:
    return json.dumps(to_dict(results, frameworks, meta), indent=2)


def to_console(results: dict[str, CheckResult], frameworks: list[FrameworkResult]) -> str:
    lines = ["", "FRAMEWORK SCORES", "-" * 64]
    for f in frameworks:
        score = "n/a" if f.score is None else f"{f.score:5.1f}%"
        lines.append(f"{f.name:<46} {score:>7}  ({f.passed} pass / {f.failed} fail / {f.not_applicable} n/a)")
    lines += ["", "FAILED CHECKS (most severe first)", "-" * 64]
    failed = [r for r in _sorted_checks(results) if r.status == Status.FAIL]
    if not failed:
        lines.append("None.")
    for r in failed:
        lines.append(f"[{r.severity.upper():<8}] {r.check_id}  {r.title}")
        for x in r.failed:
            lines.append(f"             - {x.resource}: {x.detail}")
        lines.append(f"             fix: {r.remediation}")
    counts = {s: sum(1 for r in results.values() if r.status == s) for s in Status}
    lines += ["", f"Checks: {counts[Status.PASS]} pass, {counts[Status.FAIL]} fail, "
                  f"{counts[Status.NA]} not applicable", ""]
    return "\n".join(lines)


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1c2230;--mute:#667085;--line:#e4e7ec;--pass:#177245;--fail:#b42318;--na:#667085;
--crit:#912018;--high:#b54708;--med:#946c00;--low:#475467}
@media(prefers-color-scheme:dark){:root{--bg:#10131a;--card:#181c26;--ink:#e8ebf2;--mute:#98a2b3;--line:#2a3040;--pass:#4ade80;--fail:#f87171;--na:#98a2b3;
--crit:#fca5a5;--high:#fdba74;--med:#fde047;--low:#cbd5e1}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 64px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px}
.sub{color:var(--mute);margin:0 0 24px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.score{font-size:36px;font-weight:700;line-height:1.1}.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden;margin:10px 0}
.bar>span{display:block;height:100%;background:var(--pass)}.mute{color:var(--mute);font-size:13px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}th{color:var(--mute);font-weight:600}td:first-child{white-space:nowrap}
.tag{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.PASS{color:var(--pass)}.FAIL{color:var(--fail)}.NA{color:var(--na)}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0;padding:10px 14px}
summary{cursor:pointer;font-weight:600}ul{margin:8px 0 0;padding-left:20px}code{font-size:13px}
"""


def _tag(status: str) -> str:
    cls = "NA" if status == "N/A" else status
    return f'<span class="tag {cls}">{html.escape(status)}</span>'


def to_html(results: dict[str, CheckResult], frameworks: list[FrameworkResult],
            meta: dict | None = None) -> str:
    e = html.escape
    meta = meta or {}
    when = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sub = " · ".join(e(str(v)) for v in (meta.get("account_id"), meta.get("source"), when) if v)
    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
             f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>Cloud Compliance Report</title><style>{CSS}</style></head><body><main>",
             "<h1>Cloud Compliance Report</h1>", f"<p class='sub'>{sub}</p><div class='grid'>"]
    for f in frameworks:
        score = "n/a" if f.score is None else f"{f.score:.0f}%"
        width = 0 if f.score is None else f.score
        parts.append(
            f"<div class='card'><div class='mute'>{e(f.name)}</div><div class='score'>{score}</div>"
            f"<div class='bar'><span style='width:{width}%'></span></div>"
            f"<div class='mute'>{f.passed} pass · {f.failed} fail · {f.not_applicable} not applicable</div></div>")
    parts.append("</div>")

    for f in frameworks:
        parts.append(f"<h2>{e(f.name)}</h2><p class='mute'>{e(f.disclaimer)}</p>")
        parts.append("<table><tr><th>Control</th><th>Title</th><th>Status</th><th>Checks</th></tr>")
        for c in f.controls:
            checks = ", ".join(f"<code class='{'FAIL' if s == Status.FAIL else ''}'>{e(k)}</code>"
                               for k, s in c.check_statuses.items())
            parts.append(f"<tr><td>{e(c.control_id)}</td><td>{e(c.title)}</td>"
                         f"<td>{_tag(c.status.value)}</td><td>{checks}</td></tr>")
        parts.append("</table>")

    parts.append("<h2>Check details</h2>")
    for r in _sorted_checks(results):
        open_attr = " open" if r.status == Status.FAIL else ""
        parts.append(
            f"<details{open_attr}><summary>{_tag(r.status.value)} "
            f"<span class='{r.severity}'>[{e(r.severity)}]</span> {e(r.check_id)} · {e(r.title)}</summary>"
            f"<p class='mute'>{e(r.description)}</p>")
        if r.failed:
            parts.append("<ul>" + "".join(f"<li><code>{e(x.resource)}</code>: {e(x.detail)}</li>"
                                          for x in r.failed) + "</ul>")
            parts.append(f"<p><strong>Fix:</strong> {e(r.remediation)}</p>")
        elif r.status == Status.PASS:
            parts.append(f"<p class='mute'>{sum(1 for x in r.findings if x.status == Status.PASS)} resource(s) compliant.</p>")
        else:
            parts.append("<p class='mute'>No applicable resources or data not collected.</p>")
        parts.append("</details>")
    parts.append("</main></body></html>")
    return "".join(parts)
