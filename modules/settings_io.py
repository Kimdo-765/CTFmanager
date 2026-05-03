"""Settings persistence shared by api + worker.

Settings are stored in /data/settings.json (mounted on both containers).
Precedence: settings file > env var > default.

Sensitive values (api keys, auth tokens) are returned masked from
get_settings_view() — full values stay on disk.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any  # noqa: F401

SETTINGS_PATH = Path(os.environ.get("SETTINGS_PATH", "/data/settings.json"))

# (key, env_fallback, type, default)
SCHEMA: list[tuple[str, str | None, type, Any]] = [
    ("anthropic_api_key", "ANTHROPIC_API_KEY", str, ""),
    ("claude_model", "CLAUDE_MODEL", str, "claude-opus-4-7"),
    ("auth_token", "AUTH_TOKEN", str, ""),
    ("job_ttl_days", "JOB_TTL_DAYS", int, 7),
    ("job_timeout_seconds", "JOB_TIMEOUT", int, 900),
    ("worker_concurrency", "WORKER_CONCURRENCY", int, 3),
    ("callback_url", "CALLBACK_URL", str, ""),
]
_SECRET_KEYS = {"anthropic_api_key", "auth_token"}

_lock = threading.Lock()


def load_settings() -> dict[str, Any]:
    if not SETTINGS_PATH.exists():
        return {}
    try:
        return json.loads(SETTINGS_PATH.read_text())
    except Exception:
        return {}


def save_settings(d: dict[str, Any]) -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        tmp = SETTINGS_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(d, indent=2))
        tmp.replace(SETTINGS_PATH)


def get_setting(key: str) -> Any:
    settings = load_settings()
    for k, env_key, typ, default in SCHEMA:
        if k != key:
            continue
        v = settings.get(k)
        if v not in (None, ""):
            try:
                return typ(v)
            except (TypeError, ValueError):
                return v
        if env_key:
            ev = os.environ.get(env_key, "")
            if ev != "":
                try:
                    return typ(ev)
                except (TypeError, ValueError):
                    return ev
        return default
    return None


def apply_to_env() -> None:
    """Push current settings into the process env so libraries that read
    `os.environ["ANTHROPIC_API_KEY"]` (etc.) see them.

    Called by orchestrators at the start of each job — that way the user
    can change the key via the UI and the next job picks it up without a
    container restart.

    For ANTHROPIC_API_KEY: a placeholder value (e.g. "sk-ant-...") is
    treated as unset so the SDK falls back to OAuth credentials.
    """
    for key, env_key, typ, _ in SCHEMA:
        if not env_key:
            continue
        v = get_setting(key)
        if v in (None, ""):
            continue
        if key == "anthropic_api_key":
            sv = str(v)
            if sv.startswith("sk-ant-...") or sv.endswith("..."):
                os.environ.pop(env_key, None)
                continue
        os.environ[env_key] = str(v)


def has_claude_oauth() -> bool:
    """True if the worker container has a Claude Code OAuth credentials file
    (mounted from the host's ~/.claude). Used to detect whether claude.ai
    subscription auth is available even when no API key is configured.
    """
    candidates = [
        Path("/root/.claude/.credentials.json"),
        Path("/root/.claude/credentials.json"),
        Path.home() / ".claude" / ".credentials.json",
        Path.home() / ".claude" / "credentials.json",
    ]
    for c in candidates:
        try:
            if c.is_file() and c.stat().st_size > 0:
                return True
        except Exception:
            pass
    return False


def has_anthropic_api_key() -> bool:
    """True if a real (non-placeholder) Anthropic API key is configured."""
    v = str(get_setting("anthropic_api_key") or "")
    if not v:
        return False
    if v.startswith("sk-ant-...") or v.endswith("..."):
        return False
    return True


def has_claude_auth() -> bool:
    return has_anthropic_api_key() or has_claude_oauth()


def mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}…{value[-4:]}"


def get_settings_view() -> dict[str, Any]:
    """Public view safe to send to the UI. Secrets are masked."""
    settings = load_settings()
    out: dict[str, Any] = {
        "claude_oauth_detected": has_claude_oauth(),
    }
    for key, env_key, typ, default in SCHEMA:
        raw = settings.get(key)
        env_v = os.environ.get(env_key, "") if env_key else ""
        effective_raw = raw if raw not in (None, "") else env_v if env_v else default
        try:
            effective = typ(effective_raw) if effective_raw not in (None, "") else default
        except (TypeError, ValueError):
            effective = effective_raw
        if key in _SECRET_KEYS:
            out[f"{key}_set"] = bool(raw)
            out[f"{key}_env_set"] = bool(env_v)
            out[f"{key}_masked"] = mask(str(raw or ""))
        else:
            out[key] = effective
            out[f"{key}_source"] = (
                "settings" if raw not in (None, "") else
                "env" if env_v else "default"
            )
    return out


def update_settings(patch: dict[str, Any]) -> dict[str, Any]:
    """Apply a patch. For each key in patch:
      - value is None or "" : clear the override (revert to env/default)
      - any other value     : set
    Keys not present in the patch dict are left untouched.
    """
    cur = load_settings()
    valid = {k for k, *_ in SCHEMA}
    for key, val in patch.items():
        if key not in valid:
            continue
        if val is None or (isinstance(val, str) and val == ""):
            cur.pop(key, None)
            continue
        for k, _, typ, _ in SCHEMA:
            if k == key:
                try:
                    cur[key] = typ(val)
                except (TypeError, ValueError):
                    cur[key] = val
                break
    save_settings(cur)
    return get_settings_view()
