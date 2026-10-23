"""A05 security misconfiguration: headers, cookies, errors and production settings."""

import pytest

from conftest import audit_events, login
from safenotes import create_app
from safenotes.config import ConfigError


@pytest.mark.parametrize("path", ["/login", "/register", "/does-not-exist"])
def test_security_headers_on_every_response(client, path):
    h = client.get(path).headers
    assert "default-src 'none'" in h["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert "script-src" not in h["Content-Security-Policy"]  # the app uses no JavaScript at all
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "same-origin"
    assert "Strict-Transport-Security" not in h  # only sent when HTTPS is configured


def test_private_pages_are_not_cached(alice, client):
    assert alice.get("/").headers["Cache-Control"] == "no-store"
    assert "no-store" not in client.get("/login").headers.get("Cache-Control", "")


def test_errors_do_not_leak_internals(app):
    @app.get("/boom")
    def boom():
        raise RuntimeError("database password is hunter2")

    r = app.test_client().get("/boom")
    assert r.status_code == 500
    assert "hunter2" not in r.text and "Traceback" not in r.text
    assert "Something went wrong" in r.text


def test_production_requires_a_strong_secret_key(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFENOTES_ENV", "production")
    monkeypatch.delenv("SAFENOTES_SECRET_KEY", raising=False)
    with pytest.raises(ConfigError):
        create_app(instance_path=str(tmp_path / "a"))
    monkeypatch.setenv("SAFENOTES_SECRET_KEY", "too-short")
    with pytest.raises(ConfigError):
        create_app(instance_path=str(tmp_path / "b"))


def test_production_cookie_and_hsts(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFENOTES_ENV", "production")
    monkeypatch.setenv("SAFENOTES_SECRET_KEY", "k" * 64)
    app = create_app({"TESTING": True}, instance_path=str(tmp_path / "prod"))
    assert app.config["SESSION_COOKIE_NAME"] == "__Host-session"
    assert app.config["SESSION_COOKIE_SECURE"] is True
    r = app.test_client().get("/login", base_url="https://localhost")
    assert r.headers["Strict-Transport-Security"].startswith("max-age=31536000")
    assert "Secure" in r.headers["Set-Cookie"] and "__Host-session=" in r.headers["Set-Cookie"]


def test_audit_log_lines_cannot_be_forged(app):
    login(app.test_client(), 'eve\n{"event": "login_success", "user": "admin"}', "wrong-password-xyz")
    events = audit_events(app)
    assert [e["event"] for e in events] == ["login_failure"]  # the newline stayed inside one JSON string
