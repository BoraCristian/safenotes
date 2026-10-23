"""Registration, login, logout and account management."""

from __future__ import annotations

import contextlib
import os
import re
from datetime import datetime, timezone

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, url_for

from .db import get_db
from .passwords import hash_password, password_problem, verify_password
from .security import (audit, clear_failed_logins, current_session_hash, login_required, login_user,
                       login_wait_seconds, logout_user, record_failed_login, revoke_other_sessions, safe_next)

bp = Blueprint("auth", __name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
GENERIC_LOGIN_ERROR = "Wrong username or password."


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("notes.index"))
    error = None
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if not USERNAME_RE.match(username):
            error = "Usernames are 3-32 characters: letters, digits, dot, dash or underscore."
        elif password != confirm:
            error = "The two passwords don't match."
        else:
            error = password_problem(password, username)
        if error is None:
            db = get_db()
            if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                error = "That username is taken."
            else:
                cur = db.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                                 (username, hash_password(password), now_iso()))
                db.commit()
                login_user(cur.lastrowid)
                g.user = {"id": cur.lastrowid, "username": username}
                audit("register")
                flash("Welcome! Your account is ready.", "success")
                return redirect(url_for("notes.index"))
    return render_template("auth/register.html", error=error, username=username), (400 if error else 200)


@bp.route("/login", methods=["GET", "POST"])
def login():
    next_url = safe_next(request.values.get("next"), url_for("notes.index"))
    if g.user:
        return redirect(next_url)
    error = None
    username = ""
    status = 200
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:64]
        password = request.form.get("password", "")[:256]
        wait = login_wait_seconds(username)
        if wait:
            audit("login_throttled", username=username, retry_after=wait)
            error = f"Too many failed attempts. Try again in {max(1, round(wait / 60))} minute(s)."
            status = 429
        else:
            row = get_db().execute("SELECT id, username, password_hash FROM users WHERE username = ?",
                                   (username,)).fetchone()
            if verify_password(row["password_hash"] if row else None, password):
                clear_failed_logins(username)
                login_user(row["id"])
                g.user = {"id": row["id"], "username": row["username"]}
                audit("login_success")
                return redirect(next_url)
            record_failed_login(username)
            audit("login_failure", username=username)
            error = GENERIC_LOGIN_ERROR  # same message whether or not the user exists
            status = 401
    response = current_app.make_response((render_template("auth/login.html", error=error, username=username,
                                                          next_url=next_url), status))
    if status == 429:
        response.headers["Retry-After"] = str(wait)
    return response


@bp.post("/logout")
def logout():
    if g.user:
        audit("logout")
    logout_user()
    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))


@bp.get("/account")
@login_required
def account():
    sessions = get_db().execute(
        "SELECT token_hash, created_at, last_seen, ip, user_agent FROM sessions WHERE user_id = ? ORDER BY last_seen DESC",
        (g.user["id"],),
    ).fetchall()
    current = current_session_hash()
    rows = [{
        "current": s["token_hash"] == current,
        "created": datetime.fromtimestamp(s["created_at"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "last_seen": datetime.fromtimestamp(s["last_seen"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "ip": s["ip"],
        "agent": s["user_agent"] or "unknown device",
    } for s in sessions]
    return render_template("auth/account.html", sessions=rows)


def _check_current_password(field: str = "current_password") -> bool:
    row = get_db().execute("SELECT password_hash FROM users WHERE id = ?", (g.user["id"],)).fetchone()
    return verify_password(row["password_hash"], request.form.get(field, "")[:256])


@bp.post("/account/password")
@login_required
def change_password():
    new = request.form.get("new_password", "")
    if not _check_current_password():
        audit("password_change_failed", reason="wrong current password")
        flash("Your current password is wrong.", "error")
    elif new != request.form.get("confirm", ""):
        flash("The two new passwords don't match.", "error")
    elif problem := password_problem(new, g.user["username"]):
        flash(problem, "error")
    else:
        db = get_db()
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new), g.user["id"]))
        db.commit()
        signed_out = revoke_other_sessions(g.user["id"])  # a stolen session must not survive a password change
        audit("password_changed", other_sessions_revoked=signed_out)
        flash("Password changed. Any other devices have been signed out.", "success")
    return redirect(url_for("auth.account"))


@bp.post("/account/sessions/revoke-others")
@login_required
def revoke_sessions():
    count = revoke_other_sessions(g.user["id"])
    audit("sessions_revoked", count=count)
    flash(f"Signed out {count} other session(s).", "success")
    return redirect(url_for("auth.account"))


@bp.post("/account/delete")
@login_required
def delete_account():
    if request.form.get("confirm") != "DELETE" or not _check_current_password("password"):
        flash('To delete your account, type DELETE and enter your password.', "error")
        return redirect(url_for("auth.account"))
    db = get_db()
    stored = [r["stored_name"] for r in db.execute(
        "SELECT a.stored_name FROM attachments a JOIN notes n ON n.id = a.note_id WHERE n.owner_id = ?",
        (g.user["id"],))]
    audit("account_deleted")
    db.execute("DELETE FROM users WHERE id = ?", (g.user["id"],))  # cascades to notes, shares, sessions
    db.commit()
    for name in stored:
        with contextlib.suppress(FileNotFoundError):
            os.remove(os.path.join(current_app.config["UPLOAD_FOLDER"], name))
    logout_user()
    flash("Your account and all its notes have been deleted.", "success")
    return redirect(url_for("auth.login"))
