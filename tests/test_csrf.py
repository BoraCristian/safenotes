"""Cross-site request forgery: every state-changing request needs the session's token and a same-origin request."""

from conftest import audit_events, create_note, register, token


def test_post_without_token_is_rejected(app, alice):
    r = alice.post("/notes/new", data={"title": "x", "body": "y"})
    assert r.status_code == 400 and "expired or was submitted from another site" in r.text
    assert any(e["event"] == "csrf_rejected" for e in audit_events(app))


def test_wrong_token_is_rejected(alice):
    assert alice.post("/notes/new", data={"csrf_token": "guess", "title": "x"}).status_code == 400


def test_token_from_another_session_is_rejected(app, alice, bob):
    bobs_token = token(bob)
    assert alice.post("/notes/new", data={"csrf_token": bobs_token, "title": "x"}).status_code == 400


def test_cross_origin_request_is_rejected_even_with_token(alice):
    data = {"csrf_token": token(alice), "title": "x", "body": ""}
    r = alice.post("/notes/new", data=data, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    r = alice.post("/notes/new", data=data, headers={"Origin": "http://localhost"})
    assert r.status_code == 302  # same origin is fine


def test_logout_and_delete_need_token_too(alice):
    assert alice.post("/logout").status_code == 400
    note_id = create_note(alice)
    assert alice.post(f"/notes/{note_id}/delete").status_code == 400
    assert alice.get(f"/notes/{note_id}").status_code == 200


def test_login_form_is_protected(app):
    c = app.test_client()
    assert c.post("/login", data={"username": "a", "password": "b"}).status_code == 400
    assert c.post("/register", data={"username": "a", "password": "b", "confirm": "b"}).status_code == 400


def test_get_requests_never_change_state(app, alice):
    note_id = create_note(alice)
    for path in (f"/notes/{note_id}/delete", "/logout", "/account/delete"):
        assert alice.get(path).status_code == 405
    assert alice.get(f"/notes/{note_id}").status_code == 200
