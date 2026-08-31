"""
webapp/app.py — Flask web UI for the LLM Prompt Injection Scanner

Lets you trigger scans and view results from a browser instead of the CLI.

Security note:
    This app sends live attack payloads to a real LLM API using whatever
    ANTHROPIC_API_KEY is set in the server's environment. Locally, with no
    APP_PASSWORD set, it runs open — fine on 127.0.0.1 where only you can
    reach it. If you deploy it publicly, set APP_PASSWORD so a login is
    required before anyone can trigger a scan and burn your API quota; the
    per-IP rate limit on /scan is a second layer, not a substitute for auth.
"""

import hmac
import os
import sys
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.payloads import PayloadLibrary  # noqa: E402
from scanner.runner import ScanResult, ScanRunner  # noqa: E402
from scanner.scorer import RiskScorer  # noqa: E402
from reports.report_gen import ReportGenerator  # noqa: E402


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())

# Trust one hop of X-Forwarded-* headers so rate limiting and logging see the
# real client IP when running behind a platform proxy (e.g. Render).
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

limiter = Limiter(app=app, key_func=get_remote_address, default_limits=[])

library = PayloadLibrary()
scorer = RiskScorer()

# Holds the most recent scan so /report.html can regenerate the downloadable
# report without re-running the scan. Fine for a single-user local tool;
# not meant to serve concurrent users.
LAST_RESULTS: list[ScanResult] = []


def _auth_enabled() -> bool:
    """Auth is opt-in — only enforced once an operator sets APP_PASSWORD."""
    return bool(os.environ.get("APP_PASSWORD"))


def login_required(view):
    """
    Gate a route behind the session login when APP_PASSWORD is configured.

    Security note: this is what stops a public deployment from being an
    open API-key-burning endpoint. It's a no-op for local runs that never
    set APP_PASSWORD, preserving the original zero-config local workflow.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        if _auth_enabled() and not session.get("authenticated"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login() -> str:
    """Authenticate against APP_PASSWORD using a constant-time comparison."""
    if not _auth_enabled():
        return redirect(url_for("index"))

    if request.method == "POST":
        submitted = request.form.get("password", "")
        if hmac.compare_digest(submitted, os.environ["APP_PASSWORD"]):
            session["authenticated"] = True
            return redirect(request.args.get("next") or url_for("index"))
        flash("Incorrect password.")

    return render_template("login.html")


@app.route("/logout")
def logout() -> str:
    """Clear the session so the next request has to log in again."""
    session.pop("authenticated", None)
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
@login_required
def index() -> str:
    """Render the scan form, showing whether an API key is configured."""
    return render_template(
        "index.html",
        categories=library.list_categories(),
        has_key=bool(os.environ.get("ANTHROPIC_API_KEY")),
        auth_enabled=_auth_enabled(),
    )


@app.route("/scan", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
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
        auth_enabled=_auth_enabled(),
    )


@app.route("/report.html", methods=["GET"])
@login_required
def download_report() -> str:
    """Serve the last scan as a standalone HTML report, same as main.py produces."""
    if not LAST_RESULTS:
        flash("No scan results yet — run a scan first.")
        return redirect(url_for("index"))

    html = ReportGenerator().build_html(LAST_RESULTS)
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
