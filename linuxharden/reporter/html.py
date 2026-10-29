from datetime import datetime
from pathlib import Path
from ..checks.base import CheckResult, Status
from .scoring import weighted_score


CSS = """
body { font-family: -apple-system, Segoe UI, sans-serif; max-width: 1100px;
       margin: 2em auto; padding: 0 1em; color: #222; }
h1 { border-bottom: 3px solid #333; padding-bottom: 8px; }
.summary { display: flex; gap: 1em; margin: 1em 0; }
.card { flex: 1; border: 1px solid #ddd; padding: 1em;
        border-radius: 6px; text-align: center; }
.card .num { font-size: 2em; font-weight: bold; }
.pass { color: #1a7f37; } .fail { color: #cf222e; }
.err { color: #8250df; } .skip { color: #9a6700; }
table { width: 100%; border-collapse: collapse; margin-top: 1em; }
th, td { padding: 8px; border: 1px solid #ddd; text-align: left; }
th { background: #f5f5f5; }
.badge { padding: 2px 8px; border-radius: 4px; color: #fff;
         font-size: 0.85em; }
.badge-pass { background: #1a7f37; }
.badge-fail { background: #cf222e; }
.badge-error { background: #8250df; }
.badge-skip { background: #9a6700; }
.sev-critical { font-weight: bold; color: #cf222e; }
.sev-high { color: #cf222e; }
code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }
"""


def _badge(status: Status) -> str:
    cls = f"badge-{status.value}"
    return f'<span class="badge {cls}">{status.value}</span>'


def _card(label: str, count: int, cls: str) -> str:
    return f'<div class="card"><div class="num {cls}">{count}</div>{label}</div>'


def write_html_report(results: list[CheckResult], output: Path) -> Path:
    score = weighted_score(results)
    counts = {
        s: sum(1 for r in results if r.status == s) for s in Status
    }

    rows = []
    for r in results:
        rows.append(
            f"<tr>"
            f"<td>{r.control_id}</td>"
            f"<td>{r.title}</td>"
            f"<td>{_badge(r.status)}</td>"
            f'<td class="sev-{r.severity.value}">{r.severity.value}</td>'
            f"<td>{r.detail}</td>"
            f"<td><code>{r.remediation}</code></td>"
            f"</tr>"
        )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>LinuxHarden Report</title>
<style>{CSS}</style></head>
<body>
<h1>LinuxHarden — CIS Compliance Report</h1>
<p><strong>Generated:</strong> {datetime.now().isoformat(timespec='seconds')}</p>
<p><strong>Weighted score:</strong> <span style="font-size:1.5em">{score:.1f}%</span></p>

<div class="summary">
  {_card("Passed", counts[Status.PASS], "pass")}
  {_card("Failed", counts[Status.FAIL], "fail")}
  {_card("Errors", counts[Status.ERROR], "err")}
  {_card("Skipped", counts[Status.SKIP], "skip")}
</div>

<table>
<thead><tr>
<th>Control</th><th>Title</th><th>Status</th><th>Severity</th>
<th>Detail</th><th>Remediation</th>
</tr></thead>
<tbody>
{"".join(rows)}
</tbody>
</table>
</body></html>
"""
    output.write_text(html)
    return output
