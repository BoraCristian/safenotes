"""File upload validation and storage (A04: insecure design / unrestricted upload).

Rules:
  - only a short allowlist of types
  - the type is decided from the file's actual bytes (magic numbers), and must agree with the extension;
    the browser-supplied Content-Type is ignored because the client controls it
  - files are stored under a random name, outside the static folder, without an extension,
    so nothing uploaded can ever be executed or served as a web page
"""

from __future__ import annotations

import os
import secrets

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

# mime type -> (allowed extensions, leading byte signatures)
ALLOWED = {
    "image/png": ({"png"}, (b"\x89PNG\r\n\x1a\n",)),
    "image/jpeg": ({"jpg", "jpeg"}, (b"\xff\xd8\xff",)),
    "image/gif": ({"gif"}, (b"GIF87a", b"GIF89a")),
    "application/pdf": ({"pdf"}, (b"%PDF-",)),
    "text/plain": ({"txt", "md", "log", "csv"}, ()),  # checked by decoding instead
}


class UploadRejected(ValueError):
    pass


def detect_type(data: bytes, extension: str) -> str:
    for mime, (extensions, signatures) in ALLOWED.items():
        if extension not in extensions:
            continue
        if signatures:
            if any(data.startswith(sig) for sig in signatures):
                return mime
            raise UploadRejected(f"The file's contents don't match a .{extension} file.")
        # text: must be valid UTF-8 with no NUL bytes (binary files fail this)
        if b"\x00" in data:
            raise UploadRejected("That doesn't look like a text file.")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise UploadRejected("Text files must be UTF-8.") from None
        return mime
    allowed = ", ".join(sorted(ext for exts, _ in ALLOWED.values() for ext in exts))
    raise UploadRejected(f"Files of type .{extension or '?'} aren't allowed. Allowed: {allowed}.")


def clean_name(filename: str | None) -> tuple[str, str]:
    """A display-safe name and its lower-case extension."""
    name = secure_filename(filename or "")[:100] or "file"
    extension = name.rsplit(".", 1)[1].lower() if "." in name else ""
    return name, extension


def save_upload(file: FileStorage, folder: str, max_bytes: int) -> dict:
    name, extension = clean_name(file.filename)
    data = file.stream.read(max_bytes + 1)
    if not data:
        raise UploadRejected("The file is empty.")
    if len(data) > max_bytes:
        raise UploadRejected(f"Files can be at most {max_bytes // (1024 * 1024)} MB.")
    mime = detect_type(data, extension)

    os.makedirs(folder, exist_ok=True)
    stored = secrets.token_hex(16)
    with open(os.path.join(folder, stored), "xb") as fh:  # "x": never overwrite an existing file
        fh.write(data)
    return {"stored_name": stored, "original_name": name, "mime_type": mime, "size": len(data)}
