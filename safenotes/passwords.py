"""Password hashing and policy (A02 / A07)."""

from __future__ import annotations

from importlib import resources

from werkzeug.security import check_password_hash, generate_password_hash

MIN_LENGTH = 12
MAX_LENGTH = 128  # an upper bound stops multi-megabyte "passwords" from tying up the hash function

# Werkzeug 3 uses scrypt, a memory-hard key derivation function with a random salt per password.
HASH_METHOD = "scrypt"

# Hash of a random string, checked when a username does not exist so that the response takes as long
# as a real password check. Without it, response time reveals which usernames are registered.
_DUMMY_HASH = generate_password_hash("not-a-real-password-just-for-timing", method=HASH_METHOD)

_COMMON = frozenset(
    line.strip().lower()
    for line in resources.files("safenotes").joinpath("data/common-passwords.txt").read_text("utf-8").splitlines()
    if line.strip() and not line.startswith("#")
)


def hash_password(password: str) -> str:
    return generate_password_hash(password, method=HASH_METHOD)


def verify_password(stored_hash: str | None, password: str) -> bool:
    if stored_hash is None:
        check_password_hash(_DUMMY_HASH, password)
        return False
    return check_password_hash(stored_hash, password)


def password_problem(password: str, username: str = "") -> str | None:
    """Return why a password is not acceptable, or None. Follows NIST SP 800-63B: length over complexity
    rules, and reject known-common passwords."""
    if len(password) < MIN_LENGTH:
        return f"Use at least {MIN_LENGTH} characters. A short phrase of a few words works well."
    if len(password) > MAX_LENGTH:
        return f"Use at most {MAX_LENGTH} characters."
    lowered = password.lower()
    if lowered in _COMMON:
        return "That password is on lists of commonly used passwords. Choose something less predictable."
    if username and username.lower() in lowered:
        return "Don't include your username in your password."
    if len(set(password)) < 5:
        return "That password is too repetitive."
    return None
