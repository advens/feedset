"""Load feedset.json. The manual is the closed schema."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

SECRET_KEYS = frozenset(
    {
        "key",
        "account_id",
        "license_key",
        "password",
        "token",
        "secret",
        "secret_id",
        "role_id",
        "authorization",
    }
)
EDITIONS = ("GeoLite2-City", "GeoLite2-ASN")
_NAME = set("abcdefghijklmnopqrstuvwxyz0123456789-")
_TOKEN = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-")
_MAX_BYTES = 65536


def load_config(path: Path) -> dict:
    """Return the normalized config. Refuses a secret field or a bad path."""
    raw = _read_config_text(path)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("feedset config is not json") from exc
    if not isinstance(data, dict):
        raise ValueError("feedset config must be an object")
    _reject_secrets(data)
    unknown = set(data) - {
        "enrich_config",
        "publish",
        "work",
        "output",
        "enrich",
        "min_thrt_bytes",
        "lock",
        "timeout_sync",
        "timeout_fetch",
        "timeout_sigma",
        "misp",
        "geoip",
        "overlay",
        "ua",
        "tld",
        "sigma",
        "indicators",
        "harvest",
    }
    if unknown:
        raise ValueError("feedset config has an unknown key")
    work = _abs(data.get("work"), "work")
    cfg = {
        "enrich_config": _abs(data.get("enrich_config"), "enrich_config"),
        "publish": _abs(data.get("publish"), "publish"),
        "work": work,
        "output": _abs(data.get("output"), "output"),
        "enrich": _command(data.get("enrich", "enrich"), "enrich"),
        "min_thrt_bytes": _nonneg(data.get("min_thrt_bytes", 1048576), "min_thrt_bytes"),
        "lock": _abs(data["lock"], "lock") if "lock" in data else work / "feedset.lock",
        "timeout_sync": _positive(data.get("timeout_sync", 14400), "timeout_sync"),
        "timeout_fetch": _positive(data.get("timeout_fetch", 600), "timeout_fetch"),
        "timeout_sigma": _positive(data.get("timeout_sigma", 600), "timeout_sigma"),
        "misp": _misp(data.get("misp")),
        "geoip": _geoip(data.get("geoip")),
        "overlay": _overlay(data.get("overlay")),
        "ua": _table(data.get("ua"), "ua"),
        "tld": _table(data.get("tld"), "tld"),
        "sigma": _sigma(data.get("sigma")),
        "indicators": _indicators(data.get("indicators", [])),
        "harvest": _harvest(data.get("harvest")),
    }
    return cfg


def _read_config_text(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("feedset config is unreadable")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o002:
            raise ValueError("feedset config is unreadable")
        raw = os.read(fd, _MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > _MAX_BYTES:
        raise ValueError("feedset config is unreadable")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("feedset config is unreadable") from exc


def _reject_secrets(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in SECRET_KEYS:
                raise ValueError("config must not carry a secret")
            _reject_secrets(item)
    elif isinstance(value, list):
        for item in value:
            _reject_secrets(item)


def _abs(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is missing")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} must be an absolute path")
    return path


def _command(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is missing")
    path = Path(value)
    if path.is_absolute():
        if ".." in path.parts:
            raise ValueError(f"{label} must be an absolute path")
        return value
    if "/" in value or not set(value) <= _TOKEN:
        raise ValueError(f"{label} is not a command")
    return value


def _nonneg(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _positive(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _name(value: object, default: str) -> str:
    text = default if value is None else value
    if not isinstance(text, str) or not text or not set(text) <= _NAME:
        raise ValueError("feed name is refused")
    return text


def _misp(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("misp is missing")
    unknown = set(value) - {"name", "url", "since", "dest", "layer"}
    if unknown:
        raise ValueError("misp has an unknown key")
    layer = value.get("layer", "cti")
    if layer not in ("cti", "cti_r"):
        raise ValueError("misp layer is refused")
    return {
        "name": _name(value.get("name"), "misp"),
        "url": _origin(value.get("url"), "misp url"),
        "since": _since(value.get("since")),
        "dest": _abs(value.get("dest"), "misp dest"),
        "layer": layer,
    }


def _origin(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is missing")
    if value.startswith("https://"):
        rest = value[len("https://") :]
    elif value.startswith("http://"):
        rest = value[len("http://") :]
    else:
        raise ValueError(f"{label} is refused")
    host = rest.split("/", 1)[0]
    if not host or "@" in host or "?" in rest or "#" in rest or "/" in rest:
        raise ValueError(f"{label} is refused")
    return value


def _since(value: object) -> str:
    if not isinstance(value, str) or len(value) < 2 or len(value) > 8:
        raise ValueError("misp since is missing")
    unit = value[-1]
    number = value[:-1]
    if unit not in "mhd" or not number.isdigit() or number.startswith("0"):
        raise ValueError("misp since is missing")
    return value


def _geoip(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("geoip is missing")
    if set(value) != {"dest_dir", "editions"}:
        raise ValueError("geoip has an unknown key")
    editions = value.get("editions")
    if editions != list(EDITIONS):
        raise ValueError("geoip editions are refused")
    return {"dest_dir": _abs(value.get("dest_dir"), "geoip dest_dir"), "editions": list(EDITIONS)}


def _overlay(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("overlay is missing")
    unknown = set(value) - {"name", "path", "dest"}
    if unknown:
        raise ValueError("overlay has an unknown key")
    return {
        "name": _name(value.get("name"), "overlay"),
        "path": _abs(value.get("path"), "overlay path"),
        "dest": _abs(value.get("dest"), "overlay dest"),
    }


def _table(value: object, kind: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{kind} is missing")
    unknown = set(value) - {"name", "dest", "path", "url"}
    if unknown:
        raise ValueError(f"{kind} has an unknown key")
    has_path = "path" in value
    has_url = "url" in value
    if has_path == has_url:
        raise ValueError(f"{kind} needs a path or a url")
    row = {
        "name": _name(value.get("name"), kind),
        "dest": _abs(value.get("dest"), f"{kind} dest"),
        "kind": kind,
    }
    if has_path:
        row["path"] = _abs(value.get("path"), f"{kind} path")
    else:
        row["url"] = _https(value.get("url"), f"{kind} url")
    return row


def _https(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("https://"):
        raise ValueError(f"{label} is refused")
    rest = value[len("https://") :]
    host = rest.split("/", 1)[0]
    if not host or "@" in host or "#" in rest:
        raise ValueError(f"{label} is refused")
    return value


_INDICATOR_SUFFIX = {
    "csv": (".csv",),
    "txt": (".txt",),
    "ioc": (".ioc",),
    "json": (".json",),
    "lookup": (".lookup",),
    "misp": (".misp", ".misp.json"),
    "stix": (".stix", ".stix.json"),
}


def _indicators(value: object) -> list[dict]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("indicators must be a list")
    rows = []
    seen = set()
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("indicator is missing")
        unknown = set(item) - {"name", "type", "layer", "path"}
        if unknown:
            raise ValueError("indicator has an unknown key")
        kind = item.get("type")
        if kind not in _INDICATOR_SUFFIX:
            raise ValueError("indicator type is refused")
        layer = item.get("layer", "cti")
        if layer not in ("cti", "cti_r"):
            raise ValueError("indicator layer is refused")
        name = _name(item.get("name"), "")
        if name in seen:
            raise ValueError("indicator name is repeated")
        seen.add(name)
        path = _abs(item.get("path"), "indicator path")
        suffixes = _INDICATOR_SUFFIX[kind]
        lower = path.name.lower()
        if not any(lower.endswith(suffix) for suffix in suffixes):
            raise ValueError("indicator path is refused")
        if kind == "json" and (lower.endswith(".misp.json") or lower.endswith(".stix.json")):
            raise ValueError("indicator path is refused")
        rows.append({"name": name, "type": kind, "layer": layer, "path": path})
    return rows


def _harvest(value: object) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("harvest is missing")
    unknown = set(value) - {"ref", "rules", "dest"}
    if unknown:
        raise ValueError("harvest has an unknown key")
    has_ref = "ref" in value
    has_rules = "rules" in value
    if has_ref == has_rules:
        raise ValueError("harvest needs a ref or a rules path")
    row: dict = {"dest": _abs(value.get("dest"), "harvest dest")}
    if has_rules:
        row["rules"] = _abs(value.get("rules"), "harvest rules")
        return row
    ref = value.get("ref")
    if not isinstance(ref, str) or not _ref_ok(ref):
        raise ValueError("harvest ref is refused")
    row["ref"] = ref
    return row


def _ref_ok(value: str) -> bool:
    if len(value) > 128 or ".." in value.split("/"):
        return False
    if len(value) == 40 and set(value) <= set("0123456789abcdef"):
        return True
    head, sep, tail = value.partition("/")
    kind, sep2, name = tail.partition("/")
    if head != "refs" or sep != "/" or kind not in {"heads", "tags"} or sep2 != "/" or not name:
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-")
    return set(value) <= allowed and "//" not in value


def _sigma(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("sigma is missing")
    unknown = set(value) - {"rules", "python", "module"}
    if unknown:
        raise ValueError("sigma has an unknown key")
    return {
        "rules": _abs(value.get("rules"), "sigma rules"),
        "python": _command(value.get("python"), "sigma python"),
        "module": _command(value.get("module", "sigmac"), "sigma module"),
    }
