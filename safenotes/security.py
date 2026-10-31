"""Cross-cutting security controls: sessions, CSRF, headers, login throttling, audit log, safe redirects."""

from __future__ import annotations

import functools
import hashlib
import hmac
import json
import secrets
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from flask import Flask, abort, current_app, g, redirect, request, session, url_for
from werkzeug.exceptions import HTTPException

from .db import get_db

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# ---------------------------------------------------------------------------
# audit log (A09: security logging and monitoring)
# ---------------------------------------------------------------------------

_audit_lock = threading.Lock()


def audit(event: str, **fields) -> None:
    """Append one JSON line per security event. json.dumps escapes newlines, so log injection is not possible."""
    user = g.get("user")
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        "ip": request.remote_addr if request else None,
        "user": user["username"] if user else None,
        **fields,
    }
    with _audit_lock, open(current_app.config["AUDIT_LOG"], "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, default=str) + "\n")


# ---------------------------------------------------------------------------
# server-side sessions (A07: identification and authentication failures)
# ---------------------------------------------------------------------------


def _hash_token(token: str) -> str:
    # tokens are 256-bit random values, so a fast hash is enough; a database leak exposes no usable token
    return hashlib.sha256(token.encode()).hexdigest()


def login_user(user_id: int) -> None:
    """Start a fresh session. Clearing first means a pre-login session can never become authenticated
    (no session fixation), and a new CSRF token is issued."""
    session.clear()
    token = secrets.token_urlsafe(32)
    now = time.time()
    db = get_db()
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, last_seen, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
        (_hash_token(token), user_id, now, now, request.remote_addr, (request.user_agent.string or "")[:200]),
    )
    db.commit()
    session["sid"] = token
    session["csrf"] = secrets.token_urlsafe(32)


def logout_user() -> None:
    token = session.get("sid")
    if token:
        db = get_db()
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(token),))
        db.commit()
    session.clear()


def current_session_hash() -> str | None:
    token = session.get("sid")
    return _hash_token(token) if token else None


def revoke_other_sessions(user_id: int) -> int:
    db = get_db()
    cur = db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?",
                     (user_id, current_session_hash() or ""))
    db.commit()
    return cur.rowcount


def load_user() -> None:
    g.user = None
    token = session.get("sid")
    if not token:
        return
    db = get_db()
    row = db.execute(
        "SELECT s.token_hash, s.created_at, s.last_seen, u.id, u.username "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (_hash_token(token),),
    ).fetchone()
    now = time.time()
    cfg = current_app.config
    if row is None:
        session.clear()  # revoked or unknown token
        return
    if now - row["last_seen"] > cfg["SESSION_IDLE_TIMEOUT"] or now - row["created_at"] > cfg["SESSION_ABSOLUTE_TIMEOUT"]:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
        db.commit()
        session.clear()
        return
    if now - row["last_seen"] > 60:  # avoid a write on every request
        db.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now, row["token_hash"]))
        db.commit()
    g.user = {"id": row["id"], "username": row["username"]}


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# CSRF protection (synchronizer token + Origin check)
# ---------------------------------------------------------------------------


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf() -> None:
    if request.method not in UNSAFE_METHODS:
        return
    origin = request.headers.get("Origin")
    if origin and origin != "null" and urlsplit(origin).netloc != request.host:
        audit("csrf_rejected", reason="cross-origin request", origin=origin, path=request.path)
        abort(403)
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(sent, expected):
        audit("csrf_rejected", reason="missing or wrong token", path=request.path)
        abort(400, "Your form expired or was submitted from another site. Reload the page and try again.")


# ---------------------------------------------------------------------------
# login throttling
# ---------------------------------------------------------------------------


def login_wait_seconds(username: str) -> int:
    """Seconds until another login attempt is allowed, counting per username and per IP.
    Counting by the *submitted* username (existing or not) avoids revealing which accounts exist."""
    cfg = current_app.config
    since = time.time() - cfg["LOGIN_WINDOW"]
    db = get_db()
    wait = 0
    checks = (
        ("SELECT at FROM failed_logins WHERE username = ? AND at > ? ORDER BY at DESC", username,
         cfg["LOGIN_MAX_PER_USERNAME"]),
        ("SELECT at FROM failed_logins WHERE ip = ? AND at > ? ORDER BY at DESC", request.remote_addr or "",
         cfg["LOGIN_MAX_PER_IP"]),
    )
    for query, value, limit in checks:
        rows = db.execute(query, (value, since)).fetchall()
        if len(rows) >= limit:
            # unlocked once the limit-th most recent failure leaves the window
            wait = max(wait, int(rows[limit - 1]["at"] + cfg["LOGIN_WINDOW"] - time.time()) + 1)
    return wait


def record_failed_login(username: str) -> None:
    db = get_db()
    db.execute("INSERT INTO failed_logins (username, ip, at) VALUES (?, ?, ?)",
               (username, request.remote_addr or "", time.time()))
    db.execute("DELETE FROM failed_logins WHERE at < ?", (time.time() - 24 * 3600,))
    db.commit()


def clear_failed_logins(username: str) -> None:
    db = get_db()
    db.execute("DELETE FROM failed_logins WHERE username = ?", (username,))
    db.commit()


# ---------------------------------------------------------------------------
# redirects and headers
# ---------------------------------------------------------------------------


def safe_next(target: str | None, default: str) -> str:
    """Where to go after login: only a real page of this app (A01: open redirect).

    An allowlist rather than a blocklist: the path must match one of the app's own GET routes,
    and the redirect is rebuilt with url_for() from that route. Nothing else from the user's
    string survives, so no spelling trick (//host, /\\host, schemes, encodings) can point it
    at another site. Query strings are dropped.
    """
    if not target:
        return default
    parts = urlsplit(target.strip())
    if parts.scheme or parts.netloc or not parts.path.startswith("/"):
        return default
    try:
        endpoint, values = current_app.url_map.bind("localhost").match(parts.path, method="GET")
    except HTTPException:  # no such page, wrong method, or a redirect such as a missing slash
        return default
    if endpoint == "static":
        return default
    return url_for(endpoint, **values)


CSP = ("default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'")


def set_security_headers(response):
    h = response.headers
    h.setdefault("Content-Security-Policy", CSP)  # keep a stricter policy a view already set
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "same-origin"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    if current_app.config["HSTS"]:
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if g.get("user") is not None:
        h["Cache-Control"] = "no-store"  # private pages must not be cached by browsers or proxies
    return response


def init_app(app: Flask) -> None:
    app.before_request(load_user)
    app.before_request(check_csrf)
    app.after_request(set_security_headers)
    app.jinja_env.globals["csrf_token"] = csrf_token
