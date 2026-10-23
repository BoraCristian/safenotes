"""Notes, sharing and attachments. Every route that touches a note goes through load_note()."""

from __future__ import annotations

import contextlib
import os
import sqlite3

from flask import (Blueprint, abort, current_app, flash, g, redirect, render_template, request, send_file,
                   url_for)

from .auth import now_iso
from .db import get_db
from .security import audit, login_required
from .uploads import UploadRejected, save_upload

bp = Blueprint("notes", __name__)

MAX_TITLE = 200
MAX_BODY = 20_000


# ---------------------------------------------------------------------------
# access control (A01: broken access control)
# ---------------------------------------------------------------------------


def load_note(note_id: int, *, write: bool = False) -> sqlite3.Row:
    """Return the note if the current user may read it (owner or shared with them) or, with write=True,
    modify it (owner only).

    Notes the user has no access to answer 404, exactly like notes that don't exist, so ids can't be
    probed to find out what exists. A user the note *is* shared with gets 403 when trying to modify it.
    """
    db = get_db()
    note = db.execute(
        "SELECT n.*, u.username AS owner_name FROM notes n JOIN users u ON u.id = n.owner_id WHERE n.id = ?",
        (note_id,),
    ).fetchone()
    if note is None:
        abort(404)
    if note["owner_id"] == g.user["id"]:
        return note
    shared = db.execute("SELECT 1 FROM note_shares WHERE note_id = ? AND user_id = ?",
                        (note_id, g.user["id"])).fetchone()
    if shared and not write:
        return note
    audit("access_denied", note_id=note_id, action="write" if write else "read")
    abort(403 if shared else 404)


def _form_note() -> tuple[str, str, str | None]:
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").replace("\r\n", "\n")
    if not title:
        return title, body, "Give the note a title."
    if len(title) > MAX_TITLE:
        return title, body, f"Titles can be at most {MAX_TITLE} characters."
    if len(body) > MAX_BODY:
        return title, body, f"Notes can be at most {MAX_BODY:,} characters."
    return title, body, None


def _like_pattern(text: str) -> str:
    # escape LIKE wildcards so a search for "100%" means the literal text
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


# ---------------------------------------------------------------------------
# notes
# ---------------------------------------------------------------------------


@bp.get("/")
@login_required
def index():
    q = request.args.get("q", "").strip()[:100]
    sql = ("SELECT n.id, n.title, n.updated_at, u.username AS owner_name, n.owner_id = ? AS mine "
           "FROM notes n JOIN users u ON u.id = n.owner_id "
           "WHERE (n.owner_id = ? OR n.id IN (SELECT note_id FROM note_shares WHERE user_id = ?))")
    params: list = [g.user["id"], g.user["id"], g.user["id"]]
    if q:
        sql += " AND (n.title LIKE ? ESCAPE '\\' OR n.body LIKE ? ESCAPE '\\')"
        params += [_like_pattern(q)] * 2
    sql += " ORDER BY n.updated_at DESC LIMIT 200"
    notes = get_db().execute(sql, params).fetchall()
    return render_template("notes/index.html", notes=notes, q=q)


@bp.route("/notes/new", methods=["GET", "POST"])
@login_required
def create():
    title = body = ""
    error = None
    if request.method == "POST":
        title, body, error = _form_note()
        if error is None:
            db = get_db()
            ts = now_iso()
            cur = db.execute("INSERT INTO notes (owner_id, title, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                             (g.user["id"], title, body, ts, ts))
            db.commit()
            return redirect(url_for("notes.view", note_id=cur.lastrowid))
    return render_template("notes/edit.html", note=None, title=title, body=body, error=error), (400 if error else 200)


@bp.get("/notes/<int:note_id>")
@login_required
def view(note_id: int):
    note = load_note(note_id)
    db = get_db()
    attachments = db.execute("SELECT id, original_name, mime_type, size FROM attachments WHERE note_id = ? ORDER BY id",
                             (note_id,)).fetchall()
    shares = []
    if note["owner_id"] == g.user["id"]:
        shares = db.execute("SELECT u.id, u.username FROM note_shares s JOIN users u ON u.id = s.user_id "
                            "WHERE s.note_id = ? ORDER BY u.username", (note_id,)).fetchall()
    return render_template("notes/view.html", note=note, attachments=attachments, shares=shares,
                           is_owner=note["owner_id"] == g.user["id"])


@bp.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def edit(note_id: int):
    note = load_note(note_id, write=True)
    title, body, error = note["title"], note["body"], None
    if request.method == "POST":
        title, body, error = _form_note()
        if error is None:
            db = get_db()
            db.execute("UPDATE notes SET title = ?, body = ?, updated_at = ? WHERE id = ?",
                       (title, body, now_iso(), note_id))
            db.commit()
            flash("Saved.", "success")
            return redirect(url_for("notes.view", note_id=note_id))
    return render_template("notes/edit.html", note=note, title=title, body=body, error=error), (400 if error else 200)


@bp.post("/notes/<int:note_id>/delete")
@login_required
def delete(note_id: int):
    load_note(note_id, write=True)
    db = get_db()
    stored = [r["stored_name"] for r in db.execute("SELECT stored_name FROM attachments WHERE note_id = ?", (note_id,))]
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    for name in stored:
        _remove_file(name)
    flash("Note deleted.", "success")
    return redirect(url_for("notes.index"))


# ---------------------------------------------------------------------------
# sharing
# ---------------------------------------------------------------------------


@bp.post("/notes/<int:note_id>/share")
@login_required
def share(note_id: int):
    load_note(note_id, write=True)
    username = request.form.get("username", "").strip()[:64]
    db = get_db()
    user = db.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        flash("There's no user with that name.", "error")
    elif user["id"] == g.user["id"]:
        flash("You already own this note.", "error")
    else:
        db.execute("INSERT OR IGNORE INTO note_shares (note_id, user_id) VALUES (?, ?)", (note_id, user["id"]))
        db.commit()
        audit("note_shared", note_id=note_id, with_user=user["username"])
        flash(f"Shared with {user['username']} (read-only).", "success")
    return redirect(url_for("notes.view", note_id=note_id))


@bp.post("/notes/<int:note_id>/share/<int:user_id>/revoke")
@login_required
def unshare(note_id: int, user_id: int):
    load_note(note_id, write=True)
    db = get_db()
    db.execute("DELETE FROM note_shares WHERE note_id = ? AND user_id = ?", (note_id, user_id))
    db.commit()
    flash("Sharing removed.", "success")
    return redirect(url_for("notes.view", note_id=note_id))


# ---------------------------------------------------------------------------
# attachments
# ---------------------------------------------------------------------------


def _remove_file(stored_name: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.remove(os.path.join(current_app.config["UPLOAD_FOLDER"], stored_name))


def _load_attachment(attachment_id: int, *, write: bool = False) -> sqlite3.Row:
    row = get_db().execute("SELECT * FROM attachments WHERE id = ?", (attachment_id,)).fetchone()
    if row is None:
        abort(404)
    load_note(row["note_id"], write=write)  # the attachment inherits the note's permissions
    return row


@bp.post("/notes/<int:note_id>/attachments")
@login_required
def upload(note_id: int):
    load_note(note_id, write=True)
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM attachments WHERE note_id = ?", (note_id,)).fetchone()[0]
    file = request.files.get("file")
    if count >= current_app.config["MAX_ATTACHMENTS_PER_NOTE"]:
        flash("This note already has the maximum number of attachments.", "error")
    elif file is None or not file.filename:
        flash("Choose a file to upload.", "error")
    else:
        try:
            info = save_upload(file, current_app.config["UPLOAD_FOLDER"], current_app.config["MAX_UPLOAD_BYTES"])
        except UploadRejected as exc:
            audit("upload_rejected", note_id=note_id, filename=file.filename[:100], reason=str(exc))
            flash(str(exc), "error")
        else:
            db.execute("INSERT INTO attachments (note_id, stored_name, original_name, mime_type, size, created_at) "
                       "VALUES (?, ?, ?, ?, ?, ?)",
                       (note_id, info["stored_name"], info["original_name"], info["mime_type"], info["size"], now_iso()))
            db.commit()
            flash(f"Attached {info['original_name']}.", "success")
    return redirect(url_for("notes.view", note_id=note_id))


@bp.get("/attachments/<int:attachment_id>")
@login_required
def download(attachment_id: int):
    row = _load_attachment(attachment_id)
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], row["stored_name"])
    if not os.path.isfile(path):
        abort(404)
    response = send_file(path, mimetype=row["mime_type"], as_attachment=True,
                         download_name=row["original_name"], max_age=0)
    # even if a browser decided to render it, a sandboxed CSP stops any script inside from running
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return response


@bp.post("/attachments/<int:attachment_id>/delete")
@login_required
def delete_attachment(attachment_id: int):
    row = _load_attachment(attachment_id, write=True)
    db = get_db()
    db.execute("DELETE FROM attachments WHERE id = ?", (attachment_id,))
    db.commit()
    _remove_file(row["stored_name"])
    flash("Attachment removed.", "success")
    return redirect(url_for("notes.view", note_id=row["note_id"]))
