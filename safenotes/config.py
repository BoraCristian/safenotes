"""Configuration. Secrets come from the environment, never from the code."""

from __future__ import annotations

import os
import secrets
from pathlib import Path


class ConfigError(RuntimeError):
    pass


def load_config(instance_path: Path, overrides: dict | None = None) -> dict:
    env = os.environ.get("SAFENOTES_ENV", "development")
    production = env == "production"

    secret = os.environ.get("SAFENOTES_SECRET_KEY")
    if not secret:
        if production:
            raise ConfigError("SAFENOTES_SECRET_KEY must be set in production")
        # dev convenience: random key per run (everyone is logged out on restart)
        secret = secrets.token_hex(32)
    elif len(secret) < 32:
        raise ConfigError("SAFENOTES_SECRET_KEY must be at least 32 characters")

    config = {
        "ENV_NAME": env,
        "SECRET_KEY": secret,
        "DATABASE": str(instance_path / "safenotes.sqlite3"),
        "UPLOAD_FOLDER": str(instance_path / "uploads"),
        "AUDIT_LOG": str(instance_path / "audit.log"),
        # cookies: Secure + the __Host- prefix require HTTPS, so they are on in production only
        "SESSION_COOKIE_NAME": "__Host-session" if production else "session",
        "SESSION_COOKIE_SECURE": production,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "HSTS": production,
        # server-side session lifetime (seconds)
        "SESSION_IDLE_TIMEOUT": 30 * 60,
        "SESSION_ABSOLUTE_TIMEOUT": 12 * 60 * 60,
        # login throttling
        "LOGIN_WINDOW": 15 * 60,
        "LOGIN_MAX_PER_USERNAME": 5,
        "LOGIN_MAX_PER_IP": 20,
        # uploads
        "MAX_CONTENT_LENGTH": 2 * 1024 * 1024 + 64 * 1024,  # 2 MB file + form overhead
        "MAX_UPLOAD_BYTES": 2 * 1024 * 1024,
        "MAX_ATTACHMENTS_PER_NOTE": 10,
        # number of reverse proxies in front of the app (for the real client IP); 0 = none
        "TRUSTED_PROXIES": int(os.environ.get("SAFENOTES_TRUSTED_PROXIES", "0")),
    }
    config.update(overrides or {})
    return config
