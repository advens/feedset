"""feedset render and build. No network, no real enrich."""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from feedset.build import _reason, _require_overlay, _require_table, build  # noqa: E402
from feedset.cli import main  # noqa: E402
from feedset.config import load_config  # noqa: E402
from feedset.errors import Busy  # noqa: E402
from feedset.render import render  # noqa: E402

ENV = {
    "MISP_KEY": "a" * 32,
    "MAXMIND_ACCOUNT_ID": "1234567",
    "MAXMIND_LICENSE_KEY": "b" * 16 + "__",
}


def _table(path: Path, marker: str) -> None:
    path.write_text(
        json.dumps({"entries": [{"value": marker}]}) + "\n",
        encoding="utf-8",
    )


def _layout(tmp: Path) -> dict:
    work = tmp / "work"
    pub = tmp / "publish"
    rules = tmp / "rules"
    work.mkdir()
    pub.mkdir()
    rules.mkdir()
    (rules / "one.yml").write_text("title: one\n", encoding="utf-8")
    allow = work / "allow.json"
    allow.write_text(json.dumps({"entries": [{"ioc": "203.0.113.5"}]}) + "\n", encoding="utf-8")
    _table(tmp / "ua.json", "ua")
    _table(tmp / "tld.json", "tld")
    cfg = {
        "enrich_config": str(work / "enrich.json"),
        "publish": str(pub),
        "work": str(work),
        "output": str(work / "threat.thrt"),
        "enrich": "enrich",
        "min_thrt_bytes": 8,
        "misp": {
            "url": "https://misp.example",
            "since": "7d",
            "dest": str(work / "misp.misp.json"),
        },
        "geoip": {"dest_dir": str(work), "editions": ["GeoLite2-City", "GeoLite2-ASN"]},
        "overlay": {"path": str(allow), "dest": str(work / "allow.ovly")},
        "ua": {"dest": str(work / "ua.json"), "path": str(tmp / "ua.json")},
        "tld": {"dest": str(work / "tld.json"), "path": str(tmp / "tld.json")},
        "sigma": {"rules": str(rules), "python": "python3"},
    }
    path = tmp / "feedset.json"
    path.write_text(json.dumps(cfg) + "\n", encoding="utf-8")
    os.chmod(path, 0o644)
    return cfg


class ConfigTests(unittest.TestCase):
    def test_example_loads(self):
        cfg = load_config(ROOT / "docs" / "examples" / "feedset.json")
        self.assertEqual(cfg["ua"]["dest"].name, "ua.json")
        self.assertEqual(cfg["tld"]["dest"].name, "tld.json")
        self.assertEqual(cfg["geoip"]["editions"], ["GeoLite2-City", "GeoLite2-ASN"])
        self.assertNotIn("url", cfg["ua"])
        self.assertEqual(cfg["min_thrt_bytes"], 1048576)
        self.assertEqual(
            [row["name"] for row in cfg["indicators"]],
            ["indicators", "plaintext", "dictionary", "bundle", "saved-misp"],
        )
        self.assertTrue(all(row["layer"] == "cti" for row in cfg["indicators"]))

    def test_indicators_default_to_an_empty_list(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            _layout(tmp)
            cfg = load_config(tmp / "feedset.json")
            self.assertEqual(cfg["indicators"], [])

    def test_indicator_suffix_must_match_the_type(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            cfg = _layout(tmp)
            cfg["indicators"] = [
                {"name": "indicators", "type": "csv", "path": str(tmp / "indicators.txt")},
            ]
            path = tmp / "feedset.json"
            path.write_text(json.dumps(cfg) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "indicator path is refused"):
                load_config(path)

    def test_dictionary_json_rejects_a_stix_name(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            cfg = _layout(tmp)
            cfg["indicators"] = [
                {"name": "bundle", "type": "json", "path": str(tmp / "indicators.stix.json")},
            ]
            path = tmp / "feedset.json"
            path.write_text(json.dumps(cfg) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "indicator path is refused"):
                load_config(path)

    def test_secret_field_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            cfg = _layout(tmp)
            cfg["misp"]["key"] = "a" * 32
            path = tmp / "feedset.json"
            path.write_text(json.dumps(cfg) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "secret"):
                load_config(path)

    def test_world_writable_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            _layout(tmp)
            path = tmp / "feedset.json"
            os.chmod(path, 0o666)
            with self.assertRaisesRegex(ValueError, "unreadable"):
                load_config(path)

    def test_ua_is_required(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            cfg = _layout(tmp)
            del cfg["ua"]
            path = tmp / "feedset.json"
            path.write_text(json.dumps(cfg) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "ua is missing"):
                load_config(path)


    def _sigma_config(self, tmp: Path, sigma: dict) -> Path:
        cfg = _layout(tmp)
        cfg["sigma"] = dict(sigma, rules=str(tmp / "rules"))
        path = tmp / "feedset.json"
        path.write_text(json.dumps(cfg) + "\n", encoding="utf-8")
        return path

    def test_sigmac_form_loads(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            path = self._sigma_config(
                tmp,
                {
                    "sigmac": "/opt/sigma/bin/libsigma-sigmac",
                    "fields": "/etc/feeds/fields.txt",
                    "placeholders": "/etc/feeds/placeholders.yml",
                },
            )
            sigma = load_config(path)["sigma"]
            self.assertEqual(sigma["sigmac"], "/opt/sigma/bin/libsigma-sigmac")
            self.assertEqual(sigma["fields"], Path("/etc/feeds/fields.txt"))
            self.assertNotIn("python", sigma)

    def test_sigma_compiler_choice_is_checked(self):
        cases = [
            ({"python": "python3", "sigmac": "libsigma-sigmac"}, "exactly one"),
            ({}, "exactly one"),
            ({"sigmac": "libsigma-sigmac", "module": "sigmac"}, "module needs python"),
            ({"python": "python3", "fields": "/etc/feeds/fields.txt"}, "need sigmac"),
            ({"sigmac": "libsigma-sigmac", "fields": "fields.txt"}, "absolute"),
            ({"sigmac": "bin/libsigma-sigmac"}, "not a command"),
        ]
        for sigma, message in cases:
            with self.subTest(sigma=sigma), tempfile.TemporaryDirectory() as raw:
                path = self._sigma_config(Path(raw), sigma)
                with self.assertRaisesRegex(ValueError, message):
                    load_config(path)

class RenderTests(unittest.TestCase):
    def test_local_tables_are_not_enrich_rows(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            _layout(tmp)
            cfg = load_config(tmp / "feedset.json")
            render(cfg, ENV)
            document = json.loads((tmp / "work" / "enrich.json").read_text(encoding="utf-8"))
            kinds = [row["type"] for row in document["feeds"]]
            self.assertEqual(kinds, ["misp", "overlay"])
            self.assertEqual(document["feeds"][0]["key"], ENV["MISP_KEY"])
            self.assertEqual(document["geoip"]["license_key"], ENV["MAXMIND_LICENSE_KEY"])
            mode = stat.S_IMODE((tmp / "work" / "enrich.json").stat().st_mode)
            self.assertEqual(mode, 0o600)

    def test_url_tables_are_enrich_rows(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            cfg = _layout(tmp)
            cfg["ua"] = {"dest": cfg["ua"]["dest"], "url": "https://example.invalid/ua.json"}
            cfg["tld"] = {"dest": cfg["tld"]["dest"], "url": "https://example.invalid/tld.json"}
            path = tmp / "feedset.json"
            path.write_text(json.dumps(cfg) + "\n", encoding="utf-8")
            render(load_config(path), ENV)
            kinds = [row["type"] for row in json.loads((tmp / "work" / "enrich.json").read_text())["feeds"]]
            self.assertEqual(kinds, ["misp", "overlay", "ua", "tld"])

    def test_indicator_feeds_follow_the_overlay(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            cfg = _layout(tmp)
            src = tmp / "indicators.csv"
            src.write_text(
                "domain,example.invalid,70,phishing,example,green\n"
                "url,https://example.invalid/feedset,70,phishing,example,green\n",
                encoding="utf-8",
            )
            cfg["indicators"] = [{"name": "indicators", "type": "csv", "path": str(src)}]
            cfg["ua"] = {"dest": cfg["ua"]["dest"], "url": "https://example.invalid/ua.json"}
            path = tmp / "feedset.json"
            path.write_text(json.dumps(cfg) + "\n", encoding="utf-8")
            render(load_config(path), ENV)
            feeds = json.loads((tmp / "work" / "enrich.json").read_text(encoding="utf-8"))["feeds"]
            self.assertEqual([row["type"] for row in feeds], ["misp", "overlay", "csv", "ua"])
            row = feeds[2]
            self.assertEqual(row["name"], "indicators")
            self.assertEqual(row["layer"], "cti")
            self.assertEqual(row["path"], str(src))
            self.assertNotIn("url", row)
            self.assertNotIn("key", row)

    def test_refused_license_keeps_the_previous_file(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            _layout(tmp)
            dest = tmp / "work" / "enrich.json"
            dest.write_text('{"keep": true}\n', encoding="utf-8")
            os.chmod(dest, 0o600)
            bad = dict(ENV)
            bad["MAXMIND_LICENSE_KEY"] = "short"
            with self.assertRaisesRegex(ValueError, "maxmind license is missing"):
                render(load_config(tmp / "feedset.json"), bad)
            self.assertEqual(dest.read_text(encoding="utf-8"), '{"keep": true}\n')
            self.assertNotIn("short", dest.read_text(encoding="utf-8"))


class BuildTests(unittest.TestCase):
    def _run(self, tmp: Path, calls: list, **kwargs):
        cfg = load_config(tmp / "feedset.json")
        render(cfg, ENV)
        work = tmp / "work"

        def run(argv, timeout):
            calls.append(argv)
            if kwargs.get("fail") and kwargs["fail"] in argv:
                return subprocess.CompletedProcess(argv, 1, "", "enrich: no route\n")
            if "sync" in argv or (argv and argv[-1] == "build"):
                (work / "threat.thrt").write_bytes(b"x" * kwargs.get("threat", 32))
                (work / "allow.ovly").write_bytes(b"ovly")
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv and argv[-1] == "fetch":
                (work / "GeoLite2-City.mmdb").write_bytes(b"city")
                (work / "GeoLite2-ASN.mmdb").write_bytes(b"asn")
                return subprocess.CompletedProcess(argv, 0, "", "")
            if "compile" in argv:
                if kwargs.get("sigmac_fail"):
                    return subprocess.CompletedProcess(argv, 1, "", "")
                Path(argv[argv.index("-o") + 1]).write_bytes(b"sigmac")
                Path(argv[argv.index("--correlations") + 1]).write_bytes(b"{}")
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 1, "", "")

        return build(cfg, run=run, **{k: v for k, v in kwargs.items() if k in ("full", "only")})

    def test_both_generations_publish(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            _layout(tmp)
            calls: list = []
            published, errors = self._run(tmp, calls, full=True)
            self.assertEqual(errors, [])
            self.assertEqual(published, ["enrich", "detect"])
            pub = tmp / "publish"
            for name in (
                "threat.thrt",
                "threat.thrt_overlay",
                "GeoLite2-City.mmdb",
                "GeoLite2-ASN.mmdb",
                "ua.json",
                "tld.json",
                "rules.sigmac",
                "rules.corr.json",
            ):
                self.assertTrue((pub / name).is_file(), name)
                self.assertEqual(stat.S_IMODE((pub / name).stat().st_mode) & 0o077, 0o040)
            self.assertIn("--full", calls[0])
            self.assertEqual(calls[0][-2:], ["--full", "--apply"])
            self.assertEqual(json.loads((pub / "ua.json").read_text())["entries"][0]["value"], "ua")
            self.assertIn("tld", (pub / "tld.json").read_text())

    def test_sync_is_always_a_snapshot(self):
        # The build after the sync recompiles the MISP file, so an
        # incremental pull would publish only its own window.
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            _layout(tmp)
            calls: list = []
            published, errors = self._run(tmp, calls)
            self.assertEqual(errors, [])
            self.assertEqual(calls[0][-2:], ["--full", "--apply"])

    def test_short_threat_leaves_the_enrich_names(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            _layout(tmp)
            (tmp / "publish" / "threat.thrt").write_bytes(b"previous")
            published, errors = self._run(tmp, [], threat=4)
            self.assertEqual(published, ["detect"])
            self.assertIn("below the publish floor", errors[0])
            self.assertEqual((tmp / "publish" / "threat.thrt").read_bytes(), b"previous")
            self.assertTrue((tmp / "publish" / "ua.json").is_file())
            self.assertFalse((tmp / "publish" / "GeoLite2-City.mmdb").exists())

    def test_empty_table_does_not_start_sigmac(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            _layout(tmp)
            (tmp / "ua.json").write_text('{"entries": []}\n', encoding="utf-8")
            (tmp / "publish" / "rules.sigmac").write_bytes(b"previous")
            calls: list = []
            published, errors = self._run(tmp, calls)
            self.assertEqual(published, ["enrich"])
            self.assertTrue(errors)
            self.assertFalse(any("compile" in argv for argv in calls))
            self.assertEqual((tmp / "publish" / "rules.sigmac").read_bytes(), b"previous")

    def test_sigmac_failure_leaves_the_detect_names(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            _layout(tmp)
            (tmp / "publish" / "tld.json").write_text("previous\n", encoding="utf-8")
            published, errors = self._run(tmp, [], sigmac_fail=True)
            self.assertEqual(published, ["enrich"])
            self.assertEqual(errors, ["sigmac failed"])
            self.assertEqual((tmp / "publish" / "tld.json").read_text(), "previous\n")
            self.assertFalse((tmp / "publish" / "rules.sigmac").exists())

    def test_sigmac_form_runs_libsigma_sigmac(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            cfg = _layout(tmp)
            cfg["sigma"] = {
                "rules": str(tmp / "rules"),
                "sigmac": "libsigma-sigmac",
                "fields": str(tmp / "fields.txt"),
                "placeholders": str(tmp / "placeholders.yml"),
            }
            (tmp / "feedset.json").write_text(json.dumps(cfg) + "\n", encoding="utf-8")
            loaded = load_config(tmp / "feedset.json")
            render(loaded, ENV)
            calls: list = []

            def run(argv, timeout):
                calls.append(argv)
                if argv[0] == "libsigma-sigmac":
                    Path(argv[argv.index("-o") + 1]).write_bytes(b"sigmac")
                    Path(argv[argv.index("--corr") + 1]).write_bytes(b"{}")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                return subprocess.CompletedProcess(argv, 1, "", "")

            published, errors = build(loaded, run=run, only="detect")
            self.assertEqual(errors, [])
            self.assertEqual(published, ["detect"])
            argv = calls[-1]
            self.assertEqual(argv[:2], ["libsigma-sigmac", str(tmp / "rules")])
            self.assertEqual(argv[argv.index("--fields") + 1], str(tmp / "fields.txt"))
            self.assertEqual(argv[argv.index("--placeholders") + 1], str(tmp / "placeholders.yml"))
            self.assertNotIn("compile", argv)
            self.assertEqual((tmp / "publish" / "rules.sigmac").read_bytes(), b"sigmac")

    def test_busy_lock(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            _layout(tmp)
            cfg = load_config(tmp / "feedset.json")
            lock = str(cfg["lock"])
            holder = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    textwrap.dedent(
                        """\
                        import fcntl, os, sys, time
                        fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)
                        fcntl.flock(fd, fcntl.LOCK_EX)
                        sys.stdout.write("held\\n")
                        sys.stdout.flush()
                        time.sleep(30)
                        """
                    ),
                    lock,
                ],
                stdout=subprocess.PIPE,
                text=True,
            )
            try:
                line = holder.stdout.readline() if holder.stdout is not None else ""
                self.assertEqual(line.strip(), "held")
                with self.assertRaises(Busy):
                    build(cfg, run=lambda argv, timeout: subprocess.CompletedProcess(argv, 0))
            finally:
                holder.kill()
                holder.wait(timeout=5)
                if holder.stdout is not None:
                    holder.stdout.close()

    def test_reason_drops_a_key_line(self):
        text = "noise\nenrich: key=SECRET\nenrich: no route\n"
        self.assertEqual(_reason(text, "enrich sync failed"), "enrich: no route")
        self.assertNotIn("SECRET", _reason(text, "enrich sync failed"))


class ExampleTests(unittest.TestCase):
    def test_samples_are_fake_and_accepted(self):
        examples = ROOT / "docs" / "examples"
        _require_overlay(examples / "allow.json")
        _require_table(examples / "ua.json")
        _require_table(examples / "tld.json")
        banned = ("marlinos", "jourdin", "192.168.", "HttpBrowser", "mozilla")
        for path in examples.rglob("*"):
            if not path.is_file() or path.suffix not in {".json", ".yml", ".py", ".csv", ".txt", ""}:
                continue
            if path.name == "README.md":
                continue
            text = path.read_text(encoding="utf-8").lower()
            for word in banned:
                self.assertNotIn(word.lower(), text, path.name)

    def test_sample_enrich_matches_render(self):
        sample = json.loads((ROOT / "docs" / "examples" / "enrich.json").read_text(encoding="utf-8"))
        cfg = json.loads((ROOT / "docs" / "examples" / "feedset.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            cfg["enrich_config"] = str(tmp / "enrich.json")
            path = tmp / "feedset.json"
            path.write_text(json.dumps(cfg), encoding="utf-8")
            os.chmod(path, 0o644)
            render(
                load_config(path),
                {
                    "MISP_KEY": "EXAMPLEMISPKEY0000000000000001",
                    "MAXMIND_ACCOUNT_ID": "1000001",
                    "MAXMIND_LICENSE_KEY": "EXAMPLELICENSE00__",
                },
            )
            got = json.loads((tmp / "enrich.json").read_text(encoding="utf-8"))
        self.assertEqual(got, sample)

    def test_example_publishes_detect_from_indicator_files(self):
        sys.path.insert(0, str(ROOT / "docs" / "examples"))
        import run as example_run

        with tempfile.TemporaryDirectory() as raw:
            dest = Path(raw)
            config = example_run.stage(dest)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                code = example_run.execute(config)
            self.assertEqual(code, 0, stdout.getvalue())
            pub = dest / "publish"
            names = {"ua.json", "tld.json", "rules.sigmac", "rules.corr.json"}
            self.assertEqual({path.name for path in pub.iterdir() if not path.name.startswith(".")}, names)
            self.assertFalse((pub / "threat.thrt").exists())
            self.assertFalse((dest / "work" / "threat.thrt").exists())
            csv_text = (dest / "work" / "indicators.csv").read_text(encoding="utf-8")
            self.assertIn("domain,example.invalid,", csv_text)
            self.assertIn("url,https://example.invalid/feedset,", csv_text)
            misp = json.loads((dest / "work" / "sample.misp.json").read_text(encoding="utf-8"))
            values = {(row["type"], row["value"]) for row in misp["Event"]["Attribute"]}
            self.assertIn(("domain", "example.invalid"), values)
            self.assertIn(("url", "https://example.invalid/feedset"), values)
            skipped = [row for row in misp["Event"]["Attribute"] if row["value"] == "skip.example"]
            self.assertEqual(skipped[0]["to_ids"], False)
            rendered = json.loads((dest / "work" / "enrich.json").read_text(encoding="utf-8"))
            path_feeds = [row for row in rendered["feeds"] if "path" in row and row["type"] != "overlay"]
            self.assertEqual(
                [row["type"] for row in path_feeds],
                ["csv", "txt", "json", "stix", "misp"],
            )
            for row in path_feeds:
                self.assertNotIn("url", row)
                self.assertNotIn("key", row)
            self.assertEqual(
                json.loads((pub / "ua.json").read_text(encoding="utf-8"))["entries"][0]["ua"],
                "ExampleBot/1.0",
            )
            blob = stdout.getvalue()
            self.assertIn("detect: ua.json tld.json rules.sigmac rules.corr.json", blob)
            self.assertNotIn("enrich:", blob)
            self.assertNotIn("EXAMPLEMISPKEY", blob)
            self.assertNotIn("EXAMPLELICENSE", blob)


class CliTests(unittest.TestCase):
    def test_render_prints_rendered(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            _layout(tmp)
            saved = {name: os.environ.pop(name, None) for name in ENV}
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main(["render", "-c", str(tmp / "feedset.json")]), 1)
                self.assertFalse((tmp / "work" / "enrich.json").exists())
                os.environ.update(ENV)
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    code = main(["render", "-c", str(tmp / "feedset.json")])
                self.assertEqual(code, 0)
                self.assertEqual(stdout.getvalue().strip(), "rendered")
            finally:
                for name, value in saved.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value


if __name__ == "__main__":
    unittest.main()
