"""Command line. Secrets are not arguments."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from feedset.build import build
from feedset.config import load_config
from feedset.errors import Busy, FeedsetError
from feedset.harvest import harvest
from feedset.render import render

ENRICH_LINE = (
    "enrich: threat.thrt threat.thrt_overlay GeoLite2-City.mmdb GeoLite2-ASN.mmdb"
)
DETECT_LINE = "detect: ua.json tld.json rules.sigmac rules.corr.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="feedset")
    sub = parser.add_subparsers(dest="command", required=True)

    render_cmd = sub.add_parser("render", help="write enrich.json")
    render_cmd.add_argument("-c", required=True, type=Path, metavar="file")

    build_cmd = sub.add_parser("build", help="publish one or both generations")
    build_cmd.add_argument("-c", required=True, type=Path, metavar="file")
    build_cmd.add_argument("--full", action="store_true")
    build_cmd.add_argument("--only", choices=("enrich", "detect"))

    harvest_cmd = sub.add_parser("harvest", help="write ua.json and tld.json")
    harvest_cmd.add_argument("-c", required=True, type=Path, metavar="file")
    harvest_cmd.add_argument("--check", action="store_true")

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        if code is None or code == 0:
            return 0
        return 2 if code == 2 else int(code)

    try:
        cfg = load_config(args.c)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.command == "render":
        try:
            render(cfg)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print("rendered")
        return 0

    if args.command == "harvest":
        try:
            harvest(cfg, check=args.check)
        except Busy as exc:
            print(str(exc), file=sys.stderr)
            return 75
        except (ValueError, FeedsetError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        if not args.check:
            print("harvest: ua.json tld.json")
        return 0

    try:
        published, errors = build(cfg, full=args.full, only=args.only)
    except Busy as exc:
        print(str(exc), file=sys.stderr)
        return 75
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    for name in published:
        print(ENRICH_LINE if name == "enrich" else DETECT_LINE)
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
