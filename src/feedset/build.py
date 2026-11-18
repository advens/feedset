"""Publish one or both generations. A failed check renames nothing."""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from feedset.errors import Busy, FeedsetError

ENRICH_NAMES = (
    "threat.thrt",
    "threat.thrt_overlay",
    "GeoLite2-City.mmdb",
    "GeoLite2-ASN.mmdb",
)
DETECT_NAMES = ("ua.json", "tld.json", "rules.sigmac", "rules.corr.json")
_TABLE_CAP = 32 << 20

Runner = Callable[[list[str], int], subprocess.CompletedProcess[str]]


def run_cmd(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        timeout=timeout,
        capture_output=True,
        text=True,
        check=False,
    )


def build(
    cfg: dict,
    *,
    full: bool = False,
    only: str | None = None,
    run: Runner = run_cmd,
) -> tuple[list[str], list[str]]:
    """Return (published generations, errors). Holds the lock for the call."""
    if only not in (None, "enrich", "detect"):
        raise FeedsetError("only is refused")
    fd = _lock(cfg["lock"])
    try:
        return _build_locked(cfg, full=full, only=only, run=run)
    finally:
        os.close(fd)


def _lock(path: Path) -> int:
    if path.is_symlink():
        raise FeedsetError("feedset is busy")
    path.parent.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise Busy("feedset is busy") from exc
    return fd


def _build_locked(
    cfg: dict,
    *,
    full: bool,
    only: str | None,
    run: Runner,
) -> tuple[list[str], list[str]]:
    published: list[str] = []
    errors: list[str] = []
    fetched = False
    fetch_error = ""
    if only in (None, "enrich"):
        try:
            _require_overlay(cfg["overlay"]["path"])
        except FeedsetError as exc:
            errors.append(str(exc))
            if only == "enrich":
                return published, errors
        else:
            sync_error = _sync(cfg, full=full, run=run)
            build_error = "" if sync_error else _enrich_build(cfg, run=run)
            fetch_error, fetched = _fetch(cfg, only="enrich" if only == "enrich" else None, run=run)
            if sync_error or build_error or fetch_error:
                errors.append(sync_error or build_error or fetch_error)
            else:
                try:
                    _publish_enrich(cfg)
                    published.append("enrich")
                except FeedsetError as exc:
                    errors.append(str(exc))
    if only == "detect":
        fetch_error, fetched = _fetch(cfg, only="detect", run=run)
    if only in (None, "detect"):
        try:
            if fetch_error and _tables_need_fetch(cfg):
                raise FeedsetError(fetch_error)
            _publish_detect(cfg, run=run, fetched=fetched)
            published.append("detect")
        except FeedsetError as exc:
            errors.append(str(exc))
    return published, errors


def _sync(cfg: dict, *, full: bool, run: Runner) -> str:
    argv = [cfg["enrich"], "-c", str(cfg["enrich_config"]), "sync"]
    if full:
        argv.append("--full")
    argv.append("--apply")
    proc = run(argv, cfg["timeout_sync"])
    if proc.returncode != 0:
        return _reason(proc.stderr, "enrich sync failed")
    return ""


def _enrich_build(cfg: dict, *, run: Runner) -> str:
    proc = run([cfg["enrich"], "-c", str(cfg["enrich_config"]), "build"], cfg["timeout_sync"])
    if proc.returncode != 0:
        return _reason(proc.stderr, "enrich build failed")
    return ""


def _tables_need_fetch(cfg: dict) -> bool:
    return "url" in cfg["ua"] or "url" in cfg["tld"]


def _fetch(cfg: dict, *, only: str | None, run: Runner) -> tuple[str, bool]:
    """Run enrich fetch when this generation needs it. Return (error, ran)."""
    document: dict = {"output": str(cfg["output"])}
    if only != "detect":
        # The credentials are already in enrich.json. Copy that object.
        try:
            written = _read_enrich(cfg["enrich_config"])
        except FeedsetError as exc:
            return str(exc), False
        geo = written.get("geoip")
        if not isinstance(geo, dict):
            return "enrich config is unreadable", False
        document["geoip"] = geo
    feeds = []
    if only != "enrich":
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
    if feeds:
        document["feeds"] = feeds
    if "geoip" not in document and not feeds:
        return "", False
    path = _write_fetch_config(cfg["work"], document)
    try:
        proc = run([cfg["enrich"], "-c", path, "fetch"], cfg["timeout_fetch"])
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if proc.returncode != 0:
        return _reason(proc.stderr, "enrich fetch failed"), True
    return "", True


def _read_enrich(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise FeedsetError("enrich config is unreadable")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise FeedsetError("enrich config is unreadable")
        raw = os.read(fd, 1 << 20)
    finally:
        os.close(fd)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FeedsetError("enrich config is unreadable") from exc
    if not isinstance(data, dict):
        raise FeedsetError("enrich config is unreadable")
    return data


def _write_fetch_config(work: Path, document: dict) -> str:
    if work.is_symlink():
        raise FeedsetError("work directory is a symlink")
    work.mkdir(mode=0o700, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=str(work), prefix=".feedset-fetch-", suffix=".json")
    try:
        os.write(fd, (json.dumps(document) + "\n").encode("utf-8"))
        os.fchmod(fd, 0o600)
    except Exception:
        os.close(fd)
        os.unlink(name)
        raise
    os.close(fd)
    return name


def _publish_enrich(cfg: dict) -> None:
    output = cfg["output"]
    floor = cfg["min_thrt_bytes"]
    size = _regular_size(output)
    if size is None or (floor and size < floor):
        raise FeedsetError("threat.thrt is below the publish floor")
    overlay = cfg["overlay"]["dest"]
    if not _regular_size(overlay):
        raise FeedsetError("overlay is missing")
    named = {
        "threat.thrt": output,
        "threat.thrt_overlay": overlay,
    }
    dest_dir = cfg["geoip"]["dest_dir"]
    for edition in ("GeoLite2-City", "GeoLite2-ASN"):
        path = dest_dir / f"{edition}.mmdb"
        if not _regular_size(path):
            raise FeedsetError("geoip database is missing")
        named[f"{edition}.mmdb"] = path
    _publish(cfg["publish"], named)


def _publish_detect(cfg: dict, *, run: Runner, fetched: bool) -> None:
    ua = _materialize_table(cfg["ua"], fetched=fetched)
    tld = _materialize_table(cfg["tld"], fetched=fetched)
    rules = cfg["sigma"]["rules"]
    if rules.is_symlink() or not rules.is_dir():
        raise FeedsetError("sigma rules are missing")
    if not any(rules.rglob("*.yml")) and not any(rules.rglob("*.yaml")):
        raise FeedsetError("sigma rules are missing")
    parent = cfg["publish"]
    if parent.is_symlink():
        raise FeedsetError("publish directory is a symlink")
    parent.mkdir(mode=0o750, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".feedset-sigmac-", dir=str(parent)) as tmp:
        artifact = Path(tmp) / "rules.sigmac"
        corr = Path(tmp) / "rules.corr.json"
        proc = run(
            [
                cfg["sigma"]["python"],
                "-m",
                cfg["sigma"]["module"],
                "compile",
                str(rules),
                "-o",
                str(artifact),
                "--correlations",
                str(corr),
            ],
            cfg["timeout_sigma"],
        )
        if proc.returncode != 0 or not _regular_size(artifact) or not _regular_size(corr):
            raise FeedsetError("sigmac failed")
        _publish(
            parent,
            {
                "ua.json": ua,
                "tld.json": tld,
                "rules.sigmac": artifact,
                "rules.corr.json": corr,
            },
        )


def _materialize_table(row: dict, *, fetched: bool) -> Path:
    dest = row["dest"]
    if "path" in row:
        _require_table(row["path"])
        _copy_regular(row["path"], dest, 0o640)
        return dest
    if not fetched:
        raise FeedsetError(f"{row['kind']}.json is missing")
    try:
        _require_table(dest)
    except FeedsetError as exc:
        raise FeedsetError(f"{row['kind']}.json is missing") from exc
    return dest


def _require_overlay(path: Path) -> None:
    try:
        data = _load_object(path)
    except FeedsetError as exc:
        raise FeedsetError("overlay is missing") from exc
    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        raise FeedsetError("overlay is missing")


def _require_table(path: Path) -> None:
    data = _load_object(path)
    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        raise FeedsetError("table is empty")
    if "classifiers" in data and not isinstance(data["classifiers"], list):
        raise FeedsetError("table is empty")
    for key in ("contains", "prefixes", "suffixes"):
        if key in data and not isinstance(data[key], list):
            raise FeedsetError("table is empty")


def _load_object(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise FeedsetError("table is empty")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size == 0 or info.st_size > _TABLE_CAP:
            raise FeedsetError("table is empty")
        raw = os.read(fd, info.st_size)
    finally:
        os.close(fd)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FeedsetError("table is empty") from exc
    if not isinstance(data, dict):
        raise FeedsetError("table is empty")
    return data


def _regular_size(path: Path) -> int | None:
    if path.is_symlink() or not path.is_file():
        return None
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
    finally:
        os.close(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        return None
    return info.st_size


def _copy_regular(src: Path, dest: Path, mode: int) -> None:
    if dest.is_symlink():
        raise FeedsetError("publish name is a symlink")
    dest.parent.mkdir(mode=0o750, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    if tmp.is_symlink():
        raise FeedsetError("publish name is a symlink")
    in_fd = os.open(src, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        out_fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        try:
            while True:
                block = os.read(in_fd, 1 << 20)
                if not block:
                    break
                os.write(out_fd, block)
            os.fsync(out_fd)
        finally:
            os.close(out_fd)
    except Exception:
        os.close(in_fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.close(in_fd)
    os.replace(tmp, dest)
    os.chmod(dest, mode)


def _publish(dest_dir: Path, named: dict[str, Path]) -> None:
    if dest_dir.is_symlink():
        raise FeedsetError("publish directory is a symlink")
    dest_dir.mkdir(mode=0o750, exist_ok=True)
    stage = dest_dir / f".feedset-{os.getpid()}"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(mode=0o700)
    staged: list[tuple[Path, Path]] = []
    try:
        for name, src in named.items():
            if name not in ENRICH_NAMES and name not in DETECT_NAMES:
                raise FeedsetError("feed name is refused")
            target = dest_dir / name
            if target.is_symlink():
                raise FeedsetError("publish name is a symlink")
            blob = stage / name
            _copy_regular(src, blob, 0o640)
            staged.append((blob, target))
        for blob, target in staged:
            os.replace(blob, target)
            os.chmod(target, 0o640)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _reason(stderr: str, fallback: str) -> str:
    kept = ""
    for line in stderr.splitlines():
        if not line.startswith("enrich: "):
            continue
        lower = line.lower()
        if "key" in lower or "authorization" in lower:
            continue
        kept = line[:180]
    return kept or fallback
