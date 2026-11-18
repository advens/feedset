"""Stand-in for sigmac. Writes two non-empty placeholders."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if "compile" not in argv or "-o" not in argv or "--correlations" not in argv:
        print("sigmac: compile -o and --correlations are required", file=sys.stderr)
        return 2
    artifact = Path(argv[argv.index("-o") + 1])
    corr = Path(argv[argv.index("--correlations") + 1])
    artifact.parent.mkdir(parents=True, exist_ok=True)
    corr.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("feedset example sigmac\n", encoding="utf-8")
    corr.write_text(json.dumps({"example": True, "rules": []}) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
