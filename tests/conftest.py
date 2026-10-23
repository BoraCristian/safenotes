"""Shared fixtures: a fresh app per test (own temp database, uploads and audit log) and logged-in users."""

from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safenotes import create_app  # noqa: E402

PASSWORD = "purple-otter-rides-bikes"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


@pytest.fixture
def app(tmp_path):
    return create_app({"TESTING": True}, instance_path=str(tmp_path / "instance"))


@pytest.fixture
def client(app):
    return app.test_client()


def token(client, path: str = "/") -> str:
    """CSRF token, read from a real page the way a browser would get it."""
    page = client.get(path, follow_redirects=True)
    match = TOKEN_RE.search(page.text)
    assert match, f"no CSRF token on {path}"
    return match.group(1)


def post(client, path: str, data: dict | None = None, **kwargs):
    return client.post(path, data={"csrf_token": token(client), **(data or {})}, **kwargs)


def register(client, username: str, password: str = PASSWORD):
    return client.post("/register", data={"csrf_token": token(client, "/register"), "username": username,
                                          "password": password, "confirm": password})


def login(client, username: str, password: str = PASSWORD, **extra):
    return client.post("/login", data={"csrf_token": token(client, "/login"), "username": username,
                                       "password": password, **extra})


def create_note(client, title: str = "Groceries", body: str = "milk\neggs") -> int:
    r = post(client, "/notes/new", {"title": title, "body": body})
    assert r.status_code == 302, r.text
    return int(r.headers["Location"].rsplit("/", 1)[1])


def upload(client, note_id: int, data: bytes, filename: str):
    return client.post(f"/notes/{note_id}/attachments", content_type="multipart/form-data",
                       data={"csrf_token": token(client), "file": (io.BytesIO(data), filename)})


def audit_events(app) -> list[dict]:
    path = Path(app.config["AUDIT_LOG"])
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def alice(app):
    c = app.test_client()
    assert register(c, "alice").status_code == 302
    return c


@pytest.fixture
def bob(app):
    c = app.test_client()
    assert register(c, "bob").status_code == 302
    return c
