"""A04 insecure design: uploads are checked by content, stored safely and always served as downloads."""

import os
import sqlite3

import pytest

from conftest import PNG, audit_events, create_note, post, upload

JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
PDF = b"%PDF-1.7\n" + b"0" * 32
MZ_EXE = b"MZ\x90\x00" + b"\x00" * 64


def stored_files(app):
    return os.listdir(app.config["UPLOAD_FOLDER"])


@pytest.mark.parametrize("data, name, mime", [
    (PNG, "photo.png", "image/png"),
    (JPEG, "photo.JPG", "image/jpeg"),
    (PDF, "doc.pdf", "application/pdf"),
    ("héllo wörld\n".encode(), "notes.txt", "text/plain"),
])
def test_allowed_files_are_accepted(app, alice, data, name, mime):
    note_id = create_note(alice)
    r = upload(alice, note_id, data, name)
    assert "Attached" in alice.get(f"/notes/{note_id}").text, r.text
    row = sqlite3.connect(app.config["DATABASE"]).execute("SELECT mime_type, stored_name FROM attachments").fetchone()
    assert row[0] == mime
    assert len(row[1]) == 32 and "." not in row[1]  # random name, no extension


@pytest.mark.parametrize("data, name, reason", [
    (MZ_EXE, "invoice.png", "contents don't match"),  # executable renamed to .png
    (b"<html><script>alert(1)</script></html>", "page.html", "aren't allowed"),
    (b"<svg onload=alert(1)>", "image.svg", "aren't allowed"),
    (b"<?php system($_GET[1]); ?>", "shell.php", "aren't allowed"),
    (PNG, "shell.php.png.php", "aren't allowed"),
    (b"\x00\x01binary", "data.txt", "doesn't look like a text file"),
    (b"\xff\xfe\xfa", "latin.txt", "UTF-8"),
    (b"", "empty.png", "empty"),
    (PNG, "noextension", "aren't allowed"),
])
def test_dangerous_or_mismatched_files_are_rejected(app, alice, data, name, reason):
    note_id = create_note(alice)
    upload(alice, note_id, data, name)
    page = alice.get(f"/notes/{note_id}").text
    assert reason in page.replace("&#39;", "'")
    assert stored_files(app) == []
    assert any(e["event"] == "upload_rejected" for e in audit_events(app))


def test_oversized_upload_is_rejected(app, alice):
    note_id = create_note(alice)
    big = PNG + b"\x00" * (3 * 1024 * 1024)
    r = upload(alice, note_id, big, "big.png")
    assert r.status_code == 413
    assert stored_files(app) == []


def test_path_traversal_in_filename_is_neutralised(app, alice):
    note_id = create_note(alice)
    upload(alice, note_id, b"hi", "../../../../etc/passwd.txt")
    name = sqlite3.connect(app.config["DATABASE"]).execute("SELECT original_name FROM attachments").fetchone()[0]
    assert "/" not in name and ".." not in name
    assert len(stored_files(app)) == 1  # written inside the upload folder only


def test_downloads_are_forced_and_sandboxed(alice):
    note_id = create_note(alice)
    upload(alice, note_id, PNG, "photo.png")
    r = alice.get("/attachments/1")
    assert r.status_code == 200 and r.data == PNG
    assert r.headers["Content-Disposition"].startswith("attachment;")
    assert r.headers["Content-Type"] == "image/png"  # from our detection, not the uploader
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in r.headers["Content-Security-Policy"]


def test_attachment_limit_per_note(app, alice):
    app.config["MAX_ATTACHMENTS_PER_NOTE"] = 2
    note_id = create_note(alice)
    for i in range(3):
        upload(alice, note_id, PNG, f"p{i}.png")
    assert len(stored_files(app)) == 2


def test_deleting_note_or_attachment_removes_files(app, alice):
    note_id = create_note(alice)
    upload(alice, note_id, PNG, "a.png")
    upload(alice, note_id, PNG, "b.png")
    post(alice, "/attachments/1/delete")
    assert len(stored_files(app)) == 1
    post(alice, f"/notes/{note_id}/delete")
    assert stored_files(app) == []
