#!/usr/bin/env python3
"""Stage the example kit and run render, then build, with the stand-ins.

Every secret and every indicator in this kit is fake. The publish
directory is a temporary directory. Do not point a collector at it.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))

from feedset.cli import main  # noqa: E402

FAKE_ENV = {
    "MISP_KEY": "EXAMPLEMISPKEY0000000000000001",
    "MAXMIND_ACCOUNT_ID": "1000001",
    "MAXMIND_LICENSE_KEY": "EXAMPLELICENSE00__",
}


def stage(dest: Path) -> Path:
    """Copy the fake inputs into dest and write a feedset.json with absolute paths."""
    work = dest / "work"
    publish = dest / "publish"
    rules = dest / "rules"
    work.mkdir(parents=True)
    publish.mkdir()
    shutil.copytree(HERE / "rules", rules)
    allow = work / "allow.json"
    shutil.copyfile(HERE / "allow.json", allow)
    ua = dest / "ua.json"
    tld = dest / "tld.json"
    shutil.copyfile(HERE / "ua.json", ua)
    shutil.copyfile(HERE / "tld.json", tld)
    copied = {
        "indicators.csv": work / "indicators.csv",
        "indicators.txt": work / "indicators.txt",
        "indicators.json": work / "indicators.json",
        "indicators.stix.json": work / "indicators.stix.json",
        "misp.misp.json": work / "sample.misp.json",
    }
    for name, target in copied.items():
        shutil.copyfile(HERE / name, target)
    enrich = HERE / "standin" / "enrich"
    enrich.chmod(0o755)
    cfg = {
        "enrich_config": str(work / "enrich.json"),
        "publish": str(publish),
        "work": str(work),
        "output": str(work / "threat.thrt"),
        "enrich": str(enrich),
        "min_thrt_bytes": 16,
        "misp": {
            "url": "https://misp.example",
            "since": "7d",
            "dest": str(work / "misp.misp.json"),
        },
        "geoip": {
            "dest_dir": str(work),
            "editions": ["GeoLite2-City", "GeoLite2-ASN"],
        },
        "overlay": {"path": str(allow), "dest": str(work / "allow.ovly")},
        "ua": {"dest": str(work / "ua.json"), "path": str(ua)},
        "tld": {"dest": str(work / "tld.json"), "path": str(tld)},
        "indicators": [
            {"name": "indicators", "type": "csv", "path": str(copied["indicators.csv"])},
            {"name": "plaintext", "type": "txt", "path": str(copied["indicators.txt"])},
            {"name": "dictionary", "type": "json", "path": str(copied["indicators.json"])},
            {"name": "bundle", "type": "stix", "path": str(copied["indicators.stix.json"])},
            {"name": "saved-misp", "type": "misp", "path": str(copied["misp.misp.json"])},
        ],
        "sigma": {
            "rules": str(rules),
            "python": sys.executable,
            "module": "sigmac",
        },
    }
    path = dest / "feedset.json"
    path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o644)
    return path


def execute(config: Path) -> int:
    """Render, then publish the detect generation. A .thrt is not invented here."""
    standin = str(HERE / "standin")
    previous = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = standin if not previous else standin + os.pathsep + previous
    saved = {name: os.environ.get(name) for name in FAKE_ENV}
    os.environ.update(FAKE_ENV)
    try:
        rendered = main(["render", "-c", str(config)])
        if rendered != 0:
            return rendered
        return main(["build", "-c", str(config), "--only", "detect"])
    finally:
        if previous is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = previous
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def main_example() -> int:
    dest = Path(tempfile.mkdtemp(prefix="feedset-example-"))
    config = stage(dest)
    code = execute(config)
    print(f"indicators: {dest / 'work'}")
    print(f"publish: {dest / 'publish'}")
    return code


if __name__ == "__main__":
    sys.exit(main_example())
