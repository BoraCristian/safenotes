"""A03 injection: SQL is always parameterised and every value is HTML-escaped on output."""

import sqlite3

from conftest import create_note, login, post, upload


def test_sql_metacharacters_are_treated_as_plain_text(app, alice, bob):
    create_note(alice, "Alice only", "private")
    title = "Robert'); DROP TABLE notes;--"
    note_id = create_note(bob, title, "quote ' and \" and ; -- /*")
    page = bob.get(f"/notes/{note_id}").text
    assert "Robert&#39;); DROP TABLE notes;--" in page
    conn = sqlite3.connect(app.config["DATABASE"])
    assert conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 2  # table still there


def test_search_input_cannot_change_the_query(alice, bob):
    create_note(alice, "Alice only", "private")
    create_note(bob, "Bob's note", "hello")
    for q in ["' OR '1'='1", "%' OR 1=1 --", "x' UNION SELECT id, body, 1, 1, 1 FROM notes --"]:
        page = bob.get("/", query_string={"q": q})
        assert page.status_code == 200
        assert "Alice only" not in page.text


def test_like_wildcards_are_escaped(bob):
    create_note(bob, "Discount", "save 100% today")
    create_note(bob, "Other", "nothing here")
    assert "Discount" in bob.get("/?q=100%").text
    assert "Other" not in bob.get("/?q=%").text  # "%" means the literal character, not "anything"
    assert "Other" not in bob.get("/?q=_").text


def test_login_form_input_is_not_interpreted(app, alice):
    r = login(app.test_client(), "alice' --", "anything-at-all")
    assert r.status_code == 401


def test_html_in_notes_is_escaped(alice):
    note_id = create_note(alice, '<img src=x onerror="alert(1)">', "<script>alert(document.cookie)</script>")
    page = alice.get(f"/notes/{note_id}").text
    assert "<script>alert" not in page and "&lt;script&gt;alert" in page
    assert "<img src=x" not in page and "&lt;img src=x" in page
    assert "<img src=x" not in alice.get("/").text  # list page too


def test_reflected_search_term_is_escaped(alice):
    page = alice.get("/", query_string={"q": '"><script>alert(1)</script>'}).text
    assert "<script>alert(1)" not in page
    assert "&#34;&gt;&lt;script&gt;" in page


def test_attacker_controlled_filename_is_escaped(alice):
    note_id = create_note(alice)
    upload(alice, note_id, b"plain text", "<b>bold</b>.txt")
    assert "<b>bold</b>" not in alice.get(f"/notes/{note_id}").text


def test_title_length_limits(alice):
    r = post(alice, "/notes/new", {"title": "x" * 201, "body": ""})
    assert r.status_code == 400 and "at most 200" in r.text
    r = post(alice, "/notes/new", {"title": "ok", "body": "y" * 20_001})
    assert r.status_code == 400
