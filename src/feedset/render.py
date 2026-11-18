"""Write enrich.json. A refused secret does not replace the file."""

from __future__ import annotations

import json
import os
from pathlib import Path

from feedset.config import EDITIONS

_ACCOUNT_MAX = 20
_LICENSE_MIN = 16
_LICENSE_MAX = 128
_KEY_MIN = 16
_KEY_MAX = 128


def secrets_from_env(env: dict[str, str] | None = None) -> tuple[str, str, str]:
    """Return the MISP key, the account id, and the license. Or raise."""
    source = os.environ if env is None else env
    key = source.get("MISP_KEY", "")
    account = source.get("MAXMIND_ACCOUNT_ID", "")
    license_key = source.get("MAXMIND_LICENSE_KEY", "")
    if not _token(key, _KEY_MIN, _KEY_MAX):
        raise ValueError("misp key is missing")
    if not account.isdigit() or not 1 <= len(account) <= _ACCOUNT_MAX:
        raise ValueError("maxmind account is missing")
    if (
        not _LICENSE_MIN <= len(license_key) <= _LICENSE_MAX
        or any(not ch.isascii() or not (ch.isalnum() or ch == "_") for ch in license_key)
    ):
        raise ValueError("maxmind license is missing")
    return key, account, license_key


def _token(value: str, low: int, high: int) -> bool:
    return low <= len(value) <= high and value.isalnum() and value.isascii()


def enrich_document(cfg: dict, key: str, account: str, license_key: str) -> dict:
    """The enrich.json object. Local ua and tld rows are omitted."""
    misp = cfg["misp"]
    geo = cfg["geoip"]
    overlay = cfg["overlay"]
    feeds = [
        {
            "name": misp["name"],
            "type": "misp",
            "layer": misp["layer"],
            "url": misp["url"],
            "key": key,
            "since": misp["since"],
            "dest": str(misp["dest"]),
        },
        {
            "name": overlay["name"],
            "type": "overlay",
            "path": str(overlay["path"]),
            "dest": str(overlay["dest"]),
        },
    ]
    for row in cfg.get("indicators") or []:
        feeds.append(
            {
                "name": row["name"],
                "type": row["type"],
                "layer": row["layer"],
                "path": str(row["path"]),
            }
        )
    for kind in ("ua", "tld"):
        row = cfg[kind]
        if "url" not in row:
            continue
        feeds.append(
            {
                "name": row["name"],
                "type": kind,
                "url": row["url"],
                "dest": str(row["dest"]),
            }
        )
    return {
        "output": str(cfg["output"]),
        "geoip": {
            "account_id": account,
            "license_key": license_key,
            "dest_dir": str(geo["dest_dir"]),
            "editions": list(EDITIONS),
        },
        "feeds": feeds,
    }


def render(cfg: dict, env: dict[str, str] | None = None) -> None:
    """Validate, then replace enrich.json. Validation runs before the write."""
    key, account, license_key = secrets_from_env(env)
    document = enrich_document(cfg, key, account, license_key)
    text = json.dumps(document, indent=2) + "\n"
    _write_private(cfg["enrich_config"], text)


def _write_private(path: Path, text: str) -> None:
    if path.is_symlink():
        raise ValueError("enrich config is a symlink")
    path.parent.mkdir(mode=0o700, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    if tmp.is_symlink():
        raise ValueError("enrich config is a symlink")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    except Exception:
        os.close(fd)
        os.unlink(tmp)
        raise
    os.close(fd)
    if path.is_symlink():
        os.unlink(tmp)
        raise ValueError("enrich config is a symlink")
    os.replace(tmp, path)
    os.chmod(path, 0o600)
