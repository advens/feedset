"""Build ua.json and tld.json from a Sigma rules directory.

``build`` does not call this module. A download reads the public
SigmaHQ archive. A ``rules`` path reads that directory and does not
open a network connection.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from feedset.build import _lock
from feedset.errors import Busy
from feedset.sigma_yaml import YamlError, load_all

_CONNECT_TIMEOUT = 15
_DOWNLOAD_TIMEOUT = 300
_MAX_ARCHIVE = 128 * 1024 * 1024
_MAX_MEMBER = 2 * 1024 * 1024
_MIN_ARCHIVE = 4096
_REF = re.compile(r"^(refs/(heads|tags)/[A-Za-z0-9._/-]+|[0-9a-f]{40})$")
_ARCHIVE = "https://github.com/SigmaHQ/sigma/archive/{ref}.tar.gz"
_COMMIT_API = "https://api.github.com/repos/SigmaHQ/sigma/commits/{rev}"

_UA_FIELDS = frozenset({
    "c-useragent",
    "cs-user-agent",
    "cs-useragent",
    "user_agent.original",
    "user-agent",
})
_HOST_FIELDS = frozenset({
    "cs-host",
    "c-host",
    "dst_host",
    "url.domain",
    "destination.domain",
})
_TLD_IDS = frozenset({
    "b5de2919-b74a-4805-91a7-5049accbaefe",
    "00d0b5ab-1f55-4120-8e83-487c0a7baf19",
})
_UA_RANK = {"malware": 3, "suspicious": 2, "tool": 1}
_TLD_RANK = {"suspicious": 2, "common": 1}
_MIN_EXACT = 3
_MIN_PART = 5
_PART_CAP = 1024
# A modifier value that occurs in this User-Agent would stamp a normal browser.
_BROWSER_UA = (
    "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 "
    "(khtml, like gecko) chrome/120.0.0.0 safari/537.36"
)
_PART_LIST = {"contains": "contains", "startswith": "prefixes", "endswith": "suffixes"}


def ref_ok(value: str) -> bool:
    """True when ``value`` is a SigmaHQ ref this command will fetch."""
    if not isinstance(value, str) or len(value) > 128 or ".." in value.split("/"):
        return False
    return _REF.fullmatch(value) is not None


def archive_url(ref: str) -> str:
    if not ref_ok(ref):
        raise ValueError("harvest ref is refused")
    return _ARCHIVE.format(ref=ref)


def harvest(cfg: dict, *, check: bool = False) -> None:
    """Write both tables, or check the stamp. Leave the previous files on failure."""
    spec = cfg.get("harvest")
    if not spec:
        raise ValueError("harvest is missing")
    fd = _lock(cfg["lock"])
    try:
        if check:
            if not _current(spec):
                raise ValueError("harvest stamp differs")
            return
        _write(spec)
    finally:
        os.close(fd)


def harvest_ua(rules_root: Path) -> dict[str, Any]:
    """Return the user-agent document body without the stamp fields."""
    exact: list[dict[str, str]] = []
    parts: dict[str, list[dict[str, str]]] = {"contains": [], "prefixes": [], "suffixes": []}
    n_empty = 0
    n_encoded = 0
    for src in _yaml_files(rules_root):
        for doc in _docs(src):
            detection = doc.get("detection")
            if not isinstance(detection, dict):
                continue
            title = str(doc.get("title") or src.stem)
            rule_id = _norm_id(doc.get("id"))
            found = _ua_detection(
                detection,
                title=title,
                rule_id=rule_id,
                class_name=_ua_class(title, src),
            )
            exact.extend(found["exact"])
            for key in parts:
                parts[key].extend(found[key])
            n_empty += found["empty"]
            n_encoded += found["encoded"]
    classifiers: list[str] = []
    if n_empty:
        classifiers.append("empty")
    if n_encoded:
        classifiers.append("encoded")
    body: dict[str, Any] = {"classifiers": classifiers, "entries": _merge(exact, "ua", _UA_RANK)}
    for key, rows in parts.items():
        merged = _merge(rows, "ua", _UA_RANK)[:_PART_CAP]
        if merged:
            body[key] = merged
    return body


def harvest_tld(rules_root: Path) -> dict[str, Any]:
    """Return the suffix document body without the stamp fields."""
    exact: list[dict[str, str]] = []
    for src in _yaml_files(rules_root):
        for doc in _docs(src):
            rule_id = _norm_id(doc.get("id"))
            if rule_id not in _TLD_IDS:
                continue
            detection = doc.get("detection")
            if not isinstance(detection, dict):
                continue
            title = str(doc.get("title") or src.stem)
            exact.extend(_tld_detection(
                detection,
                title=title,
                rule_id=rule_id,
                class_name=_tld_class(rule_id, title),
            ))
    return {"classifiers": ["uncommon"], "entries": _merge(exact, "tld", _TLD_RANK)}


def _current(spec: dict) -> bool:
    pin = _read_pin(spec["dest"])
    if pin is None:
        return False
    if "rules" in spec:
        return pin == _rules_stamp(spec["rules"])
    commit = _resolve_commit(spec["ref"])
    return bool(commit) and pin == commit


def _write(spec: dict) -> None:
    dest = spec["dest"]
    if dest.is_symlink():
        raise ValueError("harvest dest is refused")
    if "rules" in spec:
        rules_root = spec["rules"]
        if rules_root.is_symlink() or not rules_root.is_dir():
            raise ValueError("harvest rules are missing")
        pin = _rules_stamp(rules_root)
        extra: dict[str, str] = {}
        ua = harvest_ua(rules_root)
        tld = harvest_tld(rules_root)
    else:
        rules_root, commit, fetched = _fetch_rules(spec["ref"])
        try:
            pin = commit or _rules_stamp(rules_root)
            extra = {"sigmahq_ref": spec["ref"]}
            if commit:
                extra["sigmahq_commit"] = commit
            ua = harvest_ua(rules_root)
            tld = harvest_tld(rules_root)
        finally:
            _remove_tree(fetched)
    if not ua["entries"]:
        raise ValueError("ua table is empty")
    if not tld["entries"]:
        raise ValueError("tld table is empty")
    built_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _publish(dest, _document("feedset-ua", built_at, ua, extra), _document("feedset-tld", built_at, tld, extra), pin)


def _document(product: str, built_at: str, body: dict, extra: dict[str, str]) -> dict:
    doc = {
        "schema": 1,
        "product": product,
        "built_at": built_at,
        "classifiers": body["classifiers"],
        "entries": body["entries"],
    }
    for key in ("contains", "prefixes", "suffixes"):
        if key in body:
            doc[key] = body[key]
    doc.update(extra)
    return doc


def _publish(dest: Path, ua: dict, tld: dict, pin: str) -> None:
    dest.mkdir(mode=0o755, parents=True, exist_ok=True)
    _atomic(dest / "ua.json", json.dumps(ua, indent=2, sort_keys=True) + "\n")
    try:
        _atomic(dest / "tld.json", json.dumps(tld, indent=2, sort_keys=True) + "\n")
    except OSError:
        raise
    _atomic(dest / "PIN", pin + "\n")


def _atomic(path: Path, text: str) -> None:
    if path.is_symlink():
        raise ValueError("harvest dest is refused")
    parent = path.parent
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    tmp = Path(name)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fchmod(fd, 0o644)
        os.close(fd)
        fd = -1
        os.replace(tmp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp.exists():
            tmp.unlink()


def _read_pin(dest: Path) -> str | None:
    path = dest / "PIN"
    if path.is_symlink() or not path.is_file():
        return None
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 128:
            return None
        raw = os.read(fd, 128)
    finally:
        os.close(fd)
    text = raw.decode("utf-8", errors="replace").strip()
    return text or None


def _rules_stamp(rules_root: Path) -> str:
    digest = hashlib.sha256()
    for path in _yaml_files(rules_root):
        rel = path.relative_to(rules_root).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _fetch_rules(ref: str) -> tuple[Path, str | None, Path]:
    blob = _curl(archive_url(ref), _DOWNLOAD_TIMEOUT, _MAX_ARCHIVE)
    if len(blob) < _MIN_ARCHIVE:
        raise ValueError("sigma archive is refused")
    commit = _resolve_commit(ref)
    root = Path(tempfile.mkdtemp(prefix="feedset-sigma-"))
    try:
        _extract_yaml(blob, root)
        return _rules_root(root), commit, root
    except Exception:
        _remove_tree(root)
        raise


def _curl(url: str, timeout: int, limit: int) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("sigma archive is refused")
    try:
        result = subprocess.run(
            [
                "curl", "-fsS", "-L",
                "--connect-timeout", str(_CONNECT_TIMEOUT),
                "--max-time", str(timeout),
                "--max-filesize", str(limit),
                "-A", "feedset/0.1.0",
                url,
            ],
            capture_output=True,
            timeout=timeout + 15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("sigma archive is refused") from exc
    if result.returncode != 0 or not result.stdout or len(result.stdout) > limit:
        raise ValueError("sigma archive is refused")
    return result.stdout


def _resolve_commit(ref: str) -> str | None:
    rev = ref.rsplit("/", 1)[-1]
    url = _COMMIT_API.format(rev=rev)
    try:
        body = _curl(url, 30, 1024 * 1024)
        data = json.loads(body.decode("utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    sha = data.get("sha") if isinstance(data, dict) else None
    if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha):
        return sha
    return None


def _extract_yaml(blob: bytes, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    try:
        archive = tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
    except tarfile.TarError as exc:
        raise ValueError("sigma archive is refused") from exc
    with archive:
        for member in archive.getmembers():
            if not member.isreg():
                continue
            name = member.name
            if not (name.endswith(".yml") or name.endswith(".yaml")):
                continue
            if member.size < 0 or member.size > _MAX_MEMBER:
                raise ValueError("sigma archive is refused")
            target = (dest / name).resolve()
            if target != dest and not str(target).startswith(str(dest.resolve()) + os.sep):
                raise ValueError("sigma archive is refused")
            src = archive.extractfile(member)
            if src is None:
                continue
            payload = src.read(_MAX_MEMBER + 1)
            if len(payload) > _MAX_MEMBER:
                raise ValueError("sigma archive is refused")
            total += len(payload)
            if total > _MAX_ARCHIVE:
                raise ValueError("sigma archive is refused")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)


def _rules_root(extracted: Path) -> Path:
    children = [path for path in extracted.iterdir() if path.is_dir() and not path.is_symlink()]
    if len(children) == 1:
        candidate = children[0] / "rules"
        if candidate.is_dir() and not candidate.is_symlink():
            return candidate
    direct = extracted / "rules"
    if direct.is_dir() and not direct.is_symlink():
        return direct
    raise ValueError("sigma archive is refused")


def _remove_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            path.rmdir()
    root.rmdir()


def _yaml_files(rules_root: Path) -> list[Path]:
    found = []
    for path in sorted(rules_root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix.lower() in {".yml", ".yaml"}:
            found.append(path)
    return found


def _docs(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        loaded = load_all(text)
    except (OSError, YamlError):
        return []
    return [doc for doc in loaded if isinstance(doc, dict) and "detection" in doc]


def _norm_id(value: object) -> str | None:
    if value is None:
        return None
    token = str(value).strip().lower()
    return token or None


def _ua_class(title: str, path: Path) -> str:
    blob = f"{title} {path.name}".lower()
    if "malware" in blob:
        return "malware"
    if "susp" in blob:
        return "suspicious"
    return "suspicious"


def _tld_class(rule_id: str | None, title: str) -> str:
    if rule_id == "00d0b5ab-1f55-4120-8e83-487c0a7baf19":
        return "suspicious"
    if rule_id == "b5de2919-b74a-4805-91a7-5049accbaefe":
        return "common"
    if "blacklist" in title.lower() or "susp" in title.lower():
        return "suspicious"
    return "common"


def _split_field(key: str) -> tuple[str, str | None]:
    base, _, mod = key.partition("|")
    return base.strip().lower(), (mod.strip().lower() or None)


def _as_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _ascii_lower(text: str) -> str:
    return "".join(chr(ord(ch) + 32) if "A" <= ch <= "Z" else ch for ch in text)


def _in_browser(text: str) -> bool:
    """True when the needle occurs in the reference browser User-Agent."""
    return _ascii_lower(text) in _BROWSER_UA


def _ua_row(text: str, *, title: str, rule_id: str | None, class_name: str) -> dict[str, str]:
    row = {"ua": text, "class": class_name, "label": title}
    if rule_id:
        row["id"] = rule_id
    return row


def _ua_detection(detection: dict, *, title: str, rule_id: str | None, class_name: str) -> dict:
    exact: list[dict[str, str]] = []
    parts: dict[str, list[dict[str, str]]] = {"contains": [], "prefixes": [], "suffixes": []}
    n_empty = 0
    n_encoded = 0
    for name, selection in detection.items():
        if name == "condition" or not isinstance(selection, dict):
            continue
        for key, raw in selection.items():
            field, mod = _split_field(str(key))
            if field not in _UA_FIELDS:
                continue
            for item in _as_list(raw):
                if item is None:
                    continue
                text = str(item)
                if mod == "endswith" and text == "=":
                    n_encoded += 1
                    continue
                if not mod and text == "":
                    n_empty += 1
                    continue
                if any(ch in text for ch in "*?"):
                    continue
                nbytes = len(text.encode("utf-8"))
                if mod is None:
                    if nbytes < _MIN_EXACT:
                        continue
                    exact.append(_ua_row(text, title=title, rule_id=rule_id, class_name=class_name))
                    continue
                bucket = _PART_LIST.get(mod)
                if bucket is None or nbytes < _MIN_PART or _in_browser(text):
                    continue
                parts[bucket].append(_ua_row(text, title=title, rule_id=rule_id, class_name=class_name))
    return {"exact": exact, "empty": n_empty, "encoded": n_encoded, **parts}


def _tld_detection(detection: dict, *, title: str, rule_id: str | None, class_name: str) -> list[dict[str, str]]:
    exact: list[dict[str, str]] = []
    for name, selection in detection.items():
        if name == "condition" or not isinstance(selection, dict):
            continue
        for key, raw in selection.items():
            field, mod = _split_field(str(key))
            if field not in _HOST_FIELDS or mod not in {None, "endswith"}:
                continue
            for item in _as_list(raw):
                if item is None:
                    continue
                label = _suffix(str(item))
                if label is None:
                    continue
                row = {"tld": label, "class": class_name, "label": title}
                if rule_id:
                    row["id"] = rule_id
                exact.append(row)
    return exact


def _suffix(text: str) -> str | None:
    raw = text.strip().lower()
    if not raw or any(ch in raw for ch in "*?"):
        return None
    raw = raw.lstrip(".")
    label = raw.rsplit(".", 1)[-1]
    if len(label) < 2 or len(label) > 63:
        return None
    if not label.isascii() or not label.isalnum() or label.isdigit():
        return None
    return label


def _merge(rows: list[dict[str, str]], field: str, rank: dict[str, int]) -> list[dict[str, str]]:
    best: dict[str, dict[str, str]] = {}
    for row in rows:
        key = row[field].lower()
        prev = best.get(key)
        if prev is None or rank.get(row["class"], 0) > rank.get(prev["class"], 0):
            best[key] = row
    return [best[key] for key in sorted(best)]
