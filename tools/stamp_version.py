#!/usr/bin/env python3
"""Stamp the man page's version and date from docwraith.py's __version__.

__version__ in docwraith.py is the single source of truth for the version. The
man page's .TH line is regenerated from it, so the version is never hand-edited
there. Run this at release time, after bumping __version__:

    python tools/stamp_version.py

The version is read by parsing the source, not by importing it, so this has no
dependencies and runs even where the scanner's optional packages are absent.
"""

import datetime
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docwraith.py"
MAN = ROOT / "man" / "docwraith.1"

# Matches the .TH line up to and including the "docwraith <version>" field, so
# the trailing section name ("User Commands") is preserved.
TH_RE = re.compile(r'^\.TH\s+DOCWRAITH\s+1\s+"[^"]*"\s+"docwraith [^"]*"', re.M)


def read_version(src: Path) -> str:
    m = re.search(r'^__version__\s*=\s*"([^"]+)"', src.read_text(encoding="utf-8"), re.M)
    if not m:
        sys.exit(f"could not find __version__ in {src}")
    return m.group(1)


def stamp_manpage(man: Path, version: str, date: str) -> bool:
    text = man.read_text(encoding="utf-8")
    new, n = TH_RE.subn(f'.TH DOCWRAITH 1 "{date}" "docwraith {version}"', text, count=1)
    if n == 0:
        sys.exit(f"could not find a .TH line to stamp in {man}")
    if new == text:
        return False
    man.write_text(new, encoding="utf-8")
    return True


def main() -> int:
    version = read_version(SRC)
    date = datetime.date.today().isoformat()
    changed = stamp_manpage(MAN, version, date)
    print(f"docwraith {version}: man page {'updated' if changed else 'already current'} ({date})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
