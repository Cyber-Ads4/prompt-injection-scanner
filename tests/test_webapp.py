"""
test_webapp.py — Smoke tests for the Flask web UI.

These tests never call the Anthropic API — they only check that the
routes render correctly and that a scan request is blocked when no
API key is configured, so they're safe to run in any environment.
"""

import os

import pytest

from webapp.app import app as flask_app


@pytest.fixture
def client():
    """Return a Flask test client with a predictable, key-free environment."""
    flask_app.config["TESTING"] = True
    os.environ.pop("ANTHROPIC_API_KEY", None)
    os.environ.pop("APP_PASSWORD", None)
    with flask_app.test_client() as client:
        yield client


def test_index_renders_scan_form(client) -> None:
    """The home page should load and list the payload categories."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"Run scan" in response.data


def test_index_warns_when_no_api_key(client) -> None:
    """Without ANTHROPIC_API_KEY set, the form should show a warning."""
    response = client.get("/")
    assert b"ANTHROPIC_API_KEY" in response.data


def test_scan_without_api_key_redirects_home(client) -> None:
    """POSTing a scan with no API key must not attempt a live API call."""
    response = client.post("/scan", data={"category": "all"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"ANTHROPIC_API_KEY is not set" in response.data


def test_report_without_prior_scan_redirects_home(client) -> None:
    """Downloading a report before any scan has run should redirect, not crash."""
    response = client.get("/report.html", follow_redirects=True)
    assert response.status_code == 200
    assert b"Run scan" in response.data


def test_index_accessible_without_app_password(client) -> None:
    """The zero-config local workflow (no APP_PASSWORD) needs no login."""
    response = client.get("/")
    assert response.status_code == 200


def test_index_requires_login_when_app_password_set(client, monkeypatch) -> None:
    """Setting APP_PASSWORD must gate every route behind a login redirect."""
    monkeypatch.setenv("APP_PASSWORD", "secret123")
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_with_correct_password_grants_access(client, monkeypatch) -> None:
    """A correct password should authenticate the session and unlock the app."""
    monkeypatch.setenv("APP_PASSWORD", "secret123")
    response = client.post(
        "/login", data={"password": "secret123"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Run scan" in response.data


def test_login_with_wrong_password_is_rejected(client, monkeypatch) -> None:
    """An incorrect password must not authenticate the session."""
    monkeypatch.setenv("APP_PASSWORD", "secret123")
    response = client.post(
        "/login", data={"password": "wrong"}, follow_redirects=True
    )
    assert b"Incorrect password" in response.data
    assert b"Run scan" not in response.data
