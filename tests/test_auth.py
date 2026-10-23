"""A02 cryptographic failures and A07 identification & authentication failures."""

import os
import sqlite3
import time

import pytest

from conftest import PNG, PASSWORD, audit_events, create_note, login, post, register, token, upload


def db(app):
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn


# --- passwords -------------------------------------------------------------


def test_passwords_are_stored_as_salted_scrypt_hashes(app, client):
    register(client, "carol")
    register(app.test_client(), "dave")  # same password
    rows = {r["username"]: r["password_hash"] for r in db(app).execute("SELECT username, password_hash FROM users")}
    assert all(h.startswith("scrypt:") for h in rows.values())
    assert PASSWORD not in "".join(rows.values())
    assert rows["carol"] != rows["dave"]  # unique salt per password


@pytest.mark.parametrize("password, message", [
    ("short", "at least 12"),
    ("password1234", "commonly used"),
    ("Password1234", "commonly used"),  # case-insensitive check
    ("my-name-is-erin-ok", "username"),
    ("aaaaaaaaaaaa", "commonly used"),
    ("aaaaaaaaaaaaaaaa", "repetitive"),
    ("ababababababab", "repetitive"),
    ("x" * 129, "at most 128"),
])
def test_weak_passwords_are_rejected(client, password, message):
    r = register(client, "erin", password)
    assert r.status_code == 400 and message in r.text


def test_mismatched_and_duplicate_registration(client, app, alice):
    r = client.post("/register", data={"csrf_token": token(client, "/register"), "username": "frank",
                                       "password": PASSWORD, "confirm": PASSWORD + "x"})
    assert "don&#39;t match" in r.text
    r = register(app.test_client(), "ALICE")  # usernames are case-insensitive
    assert r.status_code == 400 and "taken" in r.text


# --- login -----------------------------------------------------------------


def test_login_errors_do_not_reveal_which_usernames_exist(app, alice):
    wrong_password = login(app.test_client(), "alice", "not-the-password-123")
    no_such_user = login(app.test_client(), "nobody-here", "not-the-password-123")
    assert wrong_password.status_code == no_such_user.status_code == 401
    assert "Wrong username or password." in wrong_password.text
    assert "Wrong username or password." in no_such_user.text


def test_login_is_throttled_per_username(app, alice):
    attacker = app.test_client()
    for _ in range(5):
        assert login(attacker, "alice", "wrong-password-xyz").status_code == 401
    r = login(attacker, "alice")  # even the right password is refused while locked
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0
    assert "Too many failed attempts" in r.text
    assert login(app.test_client(), "bob-not-locked", "wrong-password-xyz").status_code == 401
    assert [e["event"] for e in audit_events(app)].count("login_throttled") == 1


def test_login_is_throttled_per_ip_across_usernames(app):
    attacker = app.test_client()
    for i in range(20):
        login(attacker, f"user{i}", "wrong-password-xyz")
    assert login(attacker, "someone-else", "wrong-password-xyz").status_code == 429


def test_lockout_expires(app, alice):
    attacker = app.test_client()
    for _ in range(5):
        login(attacker, "alice", "wrong-password-xyz")
    with db(app) as conn:  # pretend the failures happened 20 minutes ago
        conn.execute("UPDATE failed_logins SET at = at - 1200")
    assert login(app.test_client(), "alice").status_code == 302


def test_successful_login_and_audit(app, alice):
    c = app.test_client()
    r = login(c, "alice")
    assert r.status_code == 302 and r.headers["Location"] == "/"
    assert c.get("/").status_code == 200
    assert {"login_success", "register"} <= {e["event"] for e in audit_events(app)}


# --- sessions --------------------------------------------------------------


def session_cookie(client):
    return client.get_cookie("session").value


def test_session_cookie_flags(app, client):
    r = register(client, "gina")
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_login_starts_a_new_session(app, alice):
    c = app.test_client()
    pre_login_token = token(c, "/login")
    login(c, "alice")
    with c.session_transaction() as s:
        assert s["csrf"] != pre_login_token  # no session fixation: everything is reissued
        first_sid = s["sid"]
    post(c, "/logout")
    login(c, "alice")
    with c.session_transaction() as s:
        assert s["sid"] != first_sid


def test_logout_revokes_the_session_server_side(app, alice):
    stolen = session_cookie(alice)
    post(alice, "/logout")
    attacker = app.test_client()
    attacker.set_cookie("session", stolen)  # replaying a copied cookie after logout
    r = attacker.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_password_change_signs_out_other_sessions(app, alice):
    laptop = app.test_client()
    login(laptop, "alice")
    new = "violet-heron-sings-loudly"
    r = post(alice, "/account/password", {"current_password": PASSWORD, "new_password": new, "confirm": new})
    assert r.status_code == 302
    assert laptop.get("/").status_code == 302  # signed out
    assert alice.get("/").status_code == 200  # the session that changed it stays
    assert login(app.test_client(), "alice", new).status_code == 302


def test_password_change_requires_current_password(app, alice):
    post(alice, "/account/password", {"current_password": "wrong-one-xyz", "new_password": "violet-heron-sings-loudly",
                                      "confirm": "violet-heron-sings-loudly"})
    assert login(app.test_client(), "alice").status_code == 302  # old password still works
    assert "password_change_failed" in {e["event"] for e in audit_events(app)}


def test_idle_and_absolute_timeouts(app, alice):
    with db(app) as conn:
        conn.execute("UPDATE sessions SET last_seen = ?", (time.time() - 31 * 60,))
    assert alice.get("/").status_code == 302

    login(alice, "alice")
    with db(app) as conn:
        conn.execute("UPDATE sessions SET created_at = ?", (time.time() - 13 * 3600,))
    assert alice.get("/").status_code == 302


def test_revoke_other_sessions(app, alice):
    phone = app.test_client()
    login(phone, "alice")
    assert "this device" in alice.get("/account").text
    post(alice, "/account/sessions/revoke-others")
    assert phone.get("/").status_code == 302 and alice.get("/").status_code == 200


def test_account_deletion_removes_data_and_files(app, alice):
    note_id = create_note(alice)
    upload(alice, note_id, PNG, "pic.png")
    stored = db(app).execute("SELECT stored_name FROM attachments").fetchone()["stored_name"]
    r = post(alice, "/account/delete", {"confirm": "DELETE", "password": PASSWORD})
    assert r.status_code == 302
    conn = db(app)
    assert conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert not os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], stored))
    assert login(app.test_client(), "alice").status_code == 401


def test_account_deletion_needs_confirmation(app, alice):
    post(alice, "/account/delete", {"confirm": "delete", "password": PASSWORD})
    assert alice.get("/").status_code == 200
