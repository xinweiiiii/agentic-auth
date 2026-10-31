"""Print one version's section of CHANGELOG.md — the body of its GitHub release.

    python scripts/changelog_section.py --version 0.2.0 [--out notes.md]

Exits 1 when the version has no section: a release with no notes is a release nobody wrote
notes for, and the release workflow stops rather than publishing one.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"


def section(text: str, version: str) -> str | None:
    heading = re.compile(rf"^## \[{re.escape(version)}\][^\n]*\n", re.M)
    match = heading.search(text)
    if match is None:
        return None
    following = re.compile(r"^## \[|^\[[^\]]+\]: ", re.M).search(text, match.end())
    body = text[match.end() : following.start() if following else len(text)]
    return body.strip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--changelog", type=Path, default=CHANGELOG)
    args = parser.parse_args(argv)

    body = section(args.changelog.read_text(encoding="utf-8"), args.version)
    if body is None:
        print(f"CHANGELOG.md has no '## [{args.version}]' section", file=sys.stderr)
        return 1
    if args.out:
        args.out.write_text(body, encoding="utf-8")
    else:
        sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
