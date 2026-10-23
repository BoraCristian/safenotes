"""A01 broken access control: every note, edit, share and attachment is checked against the logged-in user."""

import pytest

from conftest import PNG, audit_events, create_note, login, post, upload


def test_anonymous_users_are_sent_to_login(client):
    r = client.get("/notes/1")
    assert r.status_code == 302 and r.headers["Location"].startswith("/login?next=/notes/1")


def test_other_users_cannot_read_or_change_a_private_note(app, alice, bob):
    note_id = create_note(alice, "Alice's diary", "secret")
    assert bob.get(f"/notes/{note_id}").status_code == 404  # same answer as a note that doesn't exist
    assert bob.get(f"/notes/{note_id}/edit").status_code == 404
    assert post(bob, f"/notes/{note_id}/edit", {"title": "pwned", "body": ""}).status_code == 404
    assert post(bob, f"/notes/{note_id}/delete").status_code == 404
    assert post(bob, f"/notes/{note_id}/share", {"username": "bob"}).status_code == 404
    assert upload(bob, note_id, PNG, "x.png").status_code == 404
    assert "secret" in alice.get(f"/notes/{note_id}").text  # untouched
    denied = [e for e in audit_events(app) if e["event"] == "access_denied"]
    assert len(denied) == 6 and denied[0]["user"] == "bob"


def test_attachments_inherit_note_permissions(app, alice, bob):
    note_id = create_note(alice)
    upload(alice, note_id, PNG, "x.png")
    assert alice.get("/attachments/1").status_code == 200
    assert bob.get("/attachments/1").status_code == 404
    assert post(bob, "/attachments/1/delete").status_code == 404


def test_search_only_covers_your_own_and_shared_notes(alice, bob):
    create_note(alice, "Alice plans", "launch codes")
    assert "Alice plans" not in bob.get("/?q=launch").text
    assert "Alice plans" in alice.get("/?q=launch").text


def test_shared_notes_are_read_only(app, alice, bob):
    note_id = create_note(alice, "Team notes", "agenda")
    upload(alice, note_id, PNG, "chart.png")
    assert post(alice, f"/notes/{note_id}/share", {"username": "bob"}).status_code == 302

    assert "agenda" in bob.get(f"/notes/{note_id}").text
    assert "shared by alice" in bob.get("/").text
    assert bob.get("/attachments/1").status_code == 200
    # bob knows the note exists, so modification attempts get 403 rather than 404
    assert bob.get(f"/notes/{note_id}/edit").status_code == 403
    assert post(bob, f"/notes/{note_id}/delete").status_code == 403
    assert post(bob, "/attachments/1/delete").status_code == 403
    assert post(bob, f"/notes/{note_id}/share", {"username": "mallory"}).status_code == 403


def test_unsharing_removes_access(app, alice, bob):
    note_id = create_note(alice)
    post(alice, f"/notes/{note_id}/share", {"username": "bob"})
    bob_id = 2
    post(alice, f"/notes/{note_id}/share/{bob_id}/revoke")
    assert bob.get(f"/notes/{note_id}").status_code == 404


def test_sharing_with_unknown_user_or_self(alice):
    note_id = create_note(alice)
    assert "no user with that name" in post(alice, f"/notes/{note_id}/share", {"username": "ghost"},
                                              follow_redirects=True).text
    assert "already own" in post(alice, f"/notes/{note_id}/share", {"username": "alice"},
                                 follow_redirects=True).text


@pytest.mark.parametrize("target, expected", [
    ("/notes/1", "/notes/1"),
    ("/?q=x", "/?q=x"),
    ("https://evil.example/phish", "/"),
    ("//evil.example/phish", "/"),
    ("/\\evil.example", "/"),
    ("javascript:alert(1)", "/"),
    (" https://evil.example", "/"),
])
def test_login_redirect_stays_on_this_site(app, alice, target, expected):
    c = app.test_client()
    r = login(c, "alice", next=target)
    assert r.headers["Location"] == expected
