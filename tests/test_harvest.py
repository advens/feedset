"""feedset harvest. Local rules only. No network and no live indicators."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "src"))

from feedset.cli import main  # noqa: E402
from feedset.config import load_config  # noqa: E402
from feedset.harvest import archive_url, harvest_tld, harvest_ua  # noqa: E402


def _config(tmp: Path, rules: Path, dest: Path) -> Path:
    work = tmp / "work"
    work.mkdir()
    cfg = {
        "enrich_config": str(work / "enrich.json"),
        "publish": str(tmp / "publish"),
        "work": str(work),
        "output": str(work / "threat.thrt"),
        "enrich": "enrich",
        "min_thrt_bytes": 8,
        "misp": {"url": "https://misp.example", "since": "7d", "dest": str(work / "misp.misp.json")},
        "geoip": {"dest_dir": str(work), "editions": ["GeoLite2-City", "GeoLite2-ASN"]},
        "overlay": {"path": str(work / "allow.json"), "dest": str(work / "allow.ovly")},
        "ua": {"dest": str(work / "ua.json"), "path": str(tmp / "ua.json")},
        "tld": {"dest": str(work / "tld.json"), "path": str(tmp / "tld.json")},
        "sigma": {"rules": str(tmp / "compiled"), "python": "python3"},
        "harvest": {"rules": str(rules), "dest": str(dest)},
    }
    (work / "allow.json").write_text('{"entries":[{"ioc":"203.0.113.5"}]}\n', encoding="utf-8")
    (tmp / "publish").mkdir()
    (tmp / "compiled").mkdir()
    (tmp / "ua.json").write_text('{"entries":[{"ua":"ExampleBot/1.0","class":"malware","label":"x"}]}\n', encoding="utf-8")
    (tmp / "tld.json").write_text('{"entries":[{"tld":"example","class":"common","label":"x"}]}\n', encoding="utf-8")
    path = tmp / "feedset.json"
    path.write_text(json.dumps(cfg) + "\n", encoding="utf-8")
    os.chmod(path, 0o644)
    return path


def _rules(root: Path) -> None:
    root.mkdir()
    (root / "example_malware.yml").write_text(
        "title: Example malware agent\n"
        "detection:\n"
        "  selection:\n"
        "    c-useragent:\n"
        "      - ExampleBot/1.0\n"
        "      - x\n"
        "    c-useragent|endswith: '='\n"
        "  condition: selection\n",
        encoding="utf-8",
    )
    (root / "example_suffix.yml").write_text(
        "title: Example public suffix\n"
        "id: b5de2919-b74a-4805-91a7-5049accbaefe\n"
        "detection:\n"
        "  selection:\n"
        "    cs-host|endswith:\n"
        "      - .example\n"
        "  condition: selection\n",
        encoding="utf-8",
    )
    (root / "example_suspicious.yml").write_text(
        "title: Example suspicious suffix\n"
        "id: 00d0b5ab-1f55-4120-8e83-487c0a7baf19\n"
        "detection:\n"
        "  selection:\n"
        "    url.domain|endswith:\n"
        "      - .test\n"
        "  condition: selection\n",
        encoding="utf-8",
    )


class HarvestTests(unittest.TestCase):
    def test_rows_use_the_fixture_strings(self):
        with tempfile.TemporaryDirectory() as raw:
            rules = Path(raw) / "rules"
            _rules(rules)
            ua = harvest_ua(rules)
            tld = harvest_tld(rules)
        self.assertEqual([row["ua"] for row in ua["entries"]], ["ExampleBot/1.0"])
        self.assertEqual(ua["entries"][0]["class"], "malware")
        self.assertEqual(ua["classifiers"], ["encoded"])
        self.assertEqual(sorted(row["tld"] for row in tld["entries"]), ["example", "test"])
        classes = {row["tld"]: row["class"] for row in tld["entries"]}
        self.assertEqual(classes["example"], "common")
        self.assertEqual(classes["test"], "suspicious")

    def test_command_writes_both_tables_and_checks_the_stamp(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            rules = tmp / "rules"
            dest = tmp / "catalog"
            _rules(rules)
            config = _config(tmp, rules, dest)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["harvest", "-c", str(config)]), 0)
            ua = json.loads((dest / "ua.json").read_text(encoding="utf-8"))
            tld = json.loads((dest / "tld.json").read_text(encoding="utf-8"))
            self.assertEqual(ua["product"], "feedset-ua")
            self.assertEqual(tld["product"], "feedset-tld")
            self.assertNotIn("sigmahq_ref", ua)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["harvest", "-c", str(config), "--check"]), 0)
            (rules / "example_malware.yml").write_text("title: broken\n", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["harvest", "-c", str(config), "--check"]), 1)
            previous = (dest / "ua.json").read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["harvest", "-c", str(config)]), 1)
            self.assertEqual((dest / "ua.json").read_bytes(), previous)

    def test_ref_is_a_public_archive_url(self):
        self.assertEqual(
            archive_url("refs/heads/master"),
            "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.tar.gz",
        )
        with self.assertRaises(ValueError):
            archive_url("../refs/heads/master")
        with self.assertRaises(ValueError):
            archive_url("https://sigma.example/archive.tar.gz")

    def test_config_refuses_both_sources(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            rules = tmp / "rules"
            dest = tmp / "catalog"
            _rules(rules)
            config = _config(tmp, rules, dest)
            data = json.loads(config.read_text(encoding="utf-8"))
            data["harvest"]["ref"] = "refs/heads/master"
            config.write_text(json.dumps(data), encoding="utf-8")
            os.chmod(config, 0o644)
            with self.assertRaises(ValueError):
                load_config(config)
