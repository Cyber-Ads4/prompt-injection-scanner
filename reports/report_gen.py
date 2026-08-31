"""
report_gen.py — HTML Report Generator

Generates a styled HTML security report from scan results.

Why HTML reports matter for portfolio:
    A professional-looking report output is the difference between
    "I wrote a script" and "I built a security tool."
    Recruiters and hiring managers can open the HTML file and immediately
    understand what the tool found — no code required.
"""

import os
from datetime import datetime
from scanner.scorer import RiskScorer


# ─── Risk Level Colors ─────────────────────────────────────────────────────────

RISK_COLORS: dict[str, str] = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#ca8a04",
    "low":      "#16a34a",
    "none":     "#6b7280",
}

RISK_BG_COLORS: dict[str, str] = {
    "critical": "#fef2f2",
    "high":     "#fff7ed",
    "medium":   "#fefce8",
    "low":      "#f0fdf4",
    "none":     "#f9fafb",
}


class ReportGenerator:
    """
    Builds an HTML security report from a list of ScanResult objects.

    Output:
        A self-contained HTML file with:
        - Executive summary (total tests, injection rate, highest risk)
        - Risk breakdown by category
        - Full results table with payload details and responses
        - OWASP LLM Top 10 reference for each finding
    """

    def __init__(self) -> None:
        self.scorer = RiskScorer()

    def generate(self, results: list, output_path: str) -> None:
        """
        Generate the HTML report and write it to disk.

        Args:
            results: List of ScanResult objects from the runner
            output_path: File path to write the HTML report to
        """
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        html = self.build_html(results)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    def build_html(self, results: list) -> str:
        """
        Build the full HTML report as a string, without writing it to disk.

        Exposed separately from generate() so callers like the web UI can
        stream the report directly to a browser response instead of a file.
        """
        summary = self.scorer.summarize(results)
        total = len(results)
        detected = sum(1 for r in results if r.injection_detected)
        detection_rate = round((detected / total * 100) if total > 0 else 0)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        rows = "\n".join(self._build_result_row(r) for r in results)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LLM Prompt Injection Scan Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f0f0f; color: #e5e5e5; padding: 40px 24px; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size: 26px; font-weight: 600; color: #fff; margin-bottom: 6px; }}
  .subtitle {{ font-size: 13px; color: #888; margin-bottom: 36px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin-bottom: 36px; }}
  .stat-card {{ background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 10px; padding: 18px 20px; }}
  .stat-label {{ font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: .08em; margin-bottom: 8px; }}
  .stat-value {{ font-size: 28px; font-weight: 600; color: #fff; }}
  .stat-sub {{ font-size: 12px; color: #666; margin-top: 4px; }}
  .section-title {{ font-size: 14px; font-weight: 600; color: #aaa; text-transform: uppercase; letter-spacing: .08em; margin-bottom: 14px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 10px 14px; background: #1a1a1a; color: #888; font-weight: 500; border-bottom: 1px solid #2a2a2a; }}
  td {{ padding: 12px 14px; border-bottom: 1px solid #1e1e1e; vertical-align: top; }}
  tr:hover td {{ background: #161616; }}
  .badge {{ display: inline-block; font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; }}
  .code-text {{ font-family: 'SF Mono', 'Consolas', monospace; font-size: 12px; color: #9ca3af; }}
  .response-text {{ font-size: 12px; color: #6b7280; max-width: 380px; line-height: 1.5; }}
  .owasp-ref {{ font-size: 11px; color: #4b5563; background: #1f2937; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
  .detected-yes {{ color: #ef4444; font-weight: 600; }}
  .detected-no  {{ color: #22c55e; }}
</style>
</head>
<body>
<div class="container">

  <h1>🔍 LLM Prompt Injection Scan Report</h1>
  <div class="subtitle">Generated: {timestamp} &nbsp;·&nbsp; Model tested: claude-haiku (customer service persona)</div>

  <div class="summary-grid">
    <div class="stat-card">
      <div class="stat-label">Total payloads</div>
      <div class="stat-value">{total}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Injections detected</div>
      <div class="stat-value" style="color:#ef4444">{detected}</div>
      <div class="stat-sub">{detection_rate}% detection rate</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Critical findings</div>
      <div class="stat-value" style="color:#dc2626">{summary.get('critical', 0)}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">High risk</div>
      <div class="stat-value" style="color:#ea580c">{summary.get('high', 0)}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Blocked / safe</div>
      <div class="stat-value" style="color:#22c55e">{summary.get('none', 0)}</div>
    </div>
  </div>

  <div class="section-title" style="margin-bottom:14px">Detailed findings</div>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Category</th>
        <th>Technique</th>
        <th>Detected</th>
        <th>Risk</th>
        <th>OWASP</th>
        <th>Response preview</th>
        <th>Reason</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <div style="margin-top:40px;font-size:12px;color:#444;border-top:1px solid #1e1e1e;padding-top:20px">
    Built with the LLM Prompt Injection Scanner · OWASP LLM Top 10 reference: <a href="https://owasp.org/www-project-top-10-for-large-language-model-applications/" style="color:#555">owasp.org</a>
  </div>

</div>
</body>
</html>"""

    def _build_result_row(self, result) -> str:
        """Build a single HTML table row for one scan result."""
        risk_color = RISK_COLORS.get(result.risk_level, "#6b7280")
        detected_html = (
            '<span class="detected-yes">⚠ Yes</span>'
            if result.injection_detected
            else '<span class="detected-no">✓ No</span>'
        )
        response_preview = (result.response_text[:180] + "...") if len(result.response_text) > 180 else result.response_text
        response_preview = response_preview.replace("<", "&lt;").replace(">", "&gt;")
        reason_short = result.detection_reason[:120] + "..." if len(result.detection_reason) > 120 else result.detection_reason

        return f"""<tr>
  <td class="code-text">{result.payload.id}</td>
  <td><span style="color:#9ca3af">{result.payload.category}</span></td>
  <td style="font-size:12px">{result.payload.technique}</td>
  <td>{detected_html}</td>
  <td><span class="badge" style="color:{risk_color};background:{RISK_BG_COLORS.get(result.risk_level,'#1f2937')}">{result.risk_level}</span></td>
  <td><span class="owasp-ref">{result.payload.owasp_ref}</span></td>
  <td class="response-text">{response_preview}</td>
  <td style="font-size:12px;color:#6b7280;max-width:200px">{reason_short}</td>
</tr>"""
