"""Terminal, JSON, and self-contained HTML output."""

from __future__ import annotations

from collections import Counter
from html import escape
import json
from typing import Iterable

from .scanner import Finding, SEVERITIES


def summary(findings: Iterable[Finding]) -> dict[str, int]:
    counts = Counter(finding.severity.lower() for finding in findings)
    return {**{severity.lower(): counts[severity.lower()] for severity in SEVERITIES},
            "total": sum(counts.values())}


def json_report(findings: list[Finding]) -> str:
    return json.dumps({"summary": summary(findings), "findings": [f.to_dict() for f in findings]}, indent=2)


def terminal_report(findings: list[Finding]) -> str:
    totals = summary(findings)
    lines = ["CloudSentry � Terraform security scan", "�" * 42,
             "  " + "  ".join(f"{key.title()}: {totals[key]}" for key in ("critical", "high", "medium", "low", "info")), ""]
    if not findings:
        lines.append("No findings at the selected severity threshold.")
    for finding in findings:
        lines.extend([f"[{finding.severity}] {finding.title}  ({finding.rule_id})",
                      f"  {finding.file}:{finding.line}  �  {finding.resource}",
                      f"  {finding.description}", f"  Fix: {finding.remediation}", ""])
    lines.append("Heuristic results; review in context. A clean scan does not prove infrastructure is secure.")
    return "\n".join(lines)


def html_report(findings: list[Finding]) -> str:
    totals = summary(findings)
    cards = []
    for finding in findings:
        cards.append(f'''<article class="finding"><div class="top"><span class="badge {finding.severity.lower()}">{escape(finding.severity)}</span><code>{escape(finding.rule_id)}</code><span class="location">{escape(finding.file)}:{finding.line}</span></div><h2>{escape(finding.title)}</h2><p>{escape(finding.description)}</p><p class="resource">{escape(finding.resource)}</p><div class="fix"><strong>Suggested fix</strong><br>{escape(finding.remediation)}</div></article>''')
    body = "\n".join(cards) if cards else '<div class="empty">No findings at the selected severity threshold.</div>'
    tiles = "".join(f'<div class="tile"><strong>{totals[key]}</strong><span>{key.title()}</span></div>' for key in ("critical", "high", "medium", "low", "info"))
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CloudSentry scan report</title>
<style>
:root{{--ink:#182235;--muted:#65728a;--line:#e3e9f1;--paper:#f5f7fb;--blue:#3268e8}}*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}header{{background:#101a2d;color:white;padding:34px max(22px,calc((100vw - 1000px)/2))}}header p{{margin:5px 0 0;color:#bdc9dc}}main{{max-width:1000px;margin:28px auto;padding:0 18px}}.summary{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:22px}}.tile,.finding,.empty{{background:white;border:1px solid var(--line);border-radius:12px}}.tile{{padding:14px 16px;display:flex;align-items:baseline;justify-content:space-between}}.tile strong{{font-size:24px}}.tile span,.location,.resource{{color:var(--muted)}}.finding{{padding:20px 22px;margin:12px 0;box-shadow:0 3px 12px #20304b08}}.top{{display:flex;gap:12px;align-items:center}}.badge{{font-size:11px;font-weight:800;letter-spacing:.06em;border-radius:20px;padding:3px 9px;background:#e9edf5;color:#39465b}}.critical{{background:#ffe4e7;color:#ae1930}}.high{{background:#fff0de;color:#a34e00}}.medium{{background:#fff8d8;color:#806000}}.low,.info{{background:#e2f2ee;color:#176953}}code{{color:#52617a}}.location{{margin-left:auto;font-size:13px}}h2{{font-size:18px;margin:12px 0 4px}}p{{margin:6px 0}}.resource{{font:13px ui-monospace,monospace}}.fix{{margin-top:13px;padding:12px 14px;border-left:3px solid var(--blue);background:#f1f5ff;border-radius:0 7px 7px 0}}.empty{{padding:28px;text-align:center;color:var(--muted)}}footer{{max-width:1000px;margin:22px auto 40px;padding:0 18px;color:var(--muted);font-size:13px}}@media(max-width:620px){{.summary{{grid-template-columns:repeat(2,1fr)}}.tile:last-child{{grid-column:span 2}}.location{{font-size:11px}}}}
</style></head><body><header><h1>CloudSentry <span style="color:#88aaff">/</span> Scan report</h1><p>Local Terraform security review � {len(findings)} finding(s)</p></header><main><section class="summary">{tiles}</section>{body}</main><footer>Heuristic results; review in context. A clean scan does not prove infrastructure is secure. Generated locally by CloudSentry.</footer></body></html>'''

