"""
webapp/app.py — Flask web UI for the LLM Prompt Injection Scanner

Lets you trigger scans and view results from a browser instead of the CLI.

Security note:
    This app sends live attack payloads to a real LLM API using whatever
    ANTHROPIC_API_KEY is set in the server's environment. It is meant to
    run locally (127.0.0.1) for your own testing — do not deploy it on a
    public network, since anyone who can reach it could trigger scans that
    consume your API key.
"""

import os
import sys

from flask import Flask, flash, redirect, render_template, request, url_for

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.payloads import PayloadLibrary  # noqa: E402
from scanner.runner import ScanResult, ScanRunner  # noqa: E402
from scanner.scorer import RiskScorer  # noqa: E402
from reports.report_gen import ReportGenerator  # noqa: E402


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())

library = PayloadLibrary()
scorer = RiskScorer()

# Holds the most recent scan so /report.html can regenerate the downloadable
# report without re-running the scan. Fine for a single-user local tool;
# not meant to serve concurrent users.
LAST_RESULTS: list[ScanResult] = []


@app.route("/", methods=["GET"])
def index() -> str:
    """Render the scan form, showing whether an API key is configured."""
    return render_template(
        "index.html",
        categories=library.list_categories(),
        has_key=bool(os.environ.get("ANTHROPIC_API_KEY")),
    )


@app.route("/scan", methods=["POST"])
def scan() -> str:
    """Run a scan for the requested category and render the results page."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        flash("ANTHROPIC_API_KEY is not set on the server. Set it and restart the app.")
        return redirect(url_for("index"))

    category = request.form.get("category", "all")
    try:
        payloads = library.get_payloads(category=category)
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("index"))

    runner = ScanRunner(verbose=False)
    results = runner.run(payloads=payloads)

    global LAST_RESULTS
    LAST_RESULTS = results

    total = len(results)
    detected = sum(1 for result in results if result.injection_detected)
    detection_rate = round((detected / total * 100) if total else 0)

    return render_template(
        "results.html",
        results=results,
        summary=scorer.summarize(results),
        total=total,
        detected=detected,
        detection_rate=detection_rate,
        category=category,
    )


@app.route("/report.html", methods=["GET"])
def download_report() -> str:
    """Serve the last scan as a standalone HTML report, same as main.py produces."""
    if not LAST_RESULTS:
        flash("No scan results yet — run a scan first.")
        return redirect(url_for("index"))

    html = ReportGenerator().build_html(LAST_RESULTS)
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
