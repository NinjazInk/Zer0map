#!/usr/bin/env python3
"""Zer0map - interactive reconnaissance framework.

Usage:
    python zer0map.py                 # interactive shell
    python zer0map.py -x "use whois; set DOMAIN example.com; run; export out.md"
    python zer0map.py -r commands.rc  # run commands from a file, one per line
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

if sys.version_info < (3, 10):
    sys.exit("Zer0map requires Python 3.10 or newer")

# Allow running from any working directory
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from core.shell import Zer0mapShell
except ImportError as exc:  # missing third-party dependency
    sys.exit(f"Missing dependency: {exc.name}. Install with: pip install -r requirements.txt")


def main() -> int:
    parser = argparse.ArgumentParser(description="Zer0map interactive recon framework")
    parser.add_argument("-x", "--execute", metavar="CMDS",
                        help="semicolon-separated commands to run non-interactively, then exit")
    parser.add_argument("-r", "--resource", metavar="FILE",
                        help="file of commands (one per line) to run, then exit")
    parser.add_argument("-q", "--quiet", action="store_true", help="don't print the banner")
    args = parser.parse_args()

    shell = Zer0mapShell()
    if not args.quiet:
        shell.banner()

    commands: list[str] = []
    if args.resource:
        try:
            commands += Path(args.resource).read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            print(f"Cannot read {args.resource}: {exc.strerror}", file=sys.stderr)
            return 1
    if args.execute:
        commands += [c for c in args.execute.split(";")]

    if commands:
        for cmd in commands:
            if not cmd.strip():
                continue
            from rich.text import Text
            from core.output import console
            console.print(Text(shell.prompt_plain(), style="bold"), Text(cmd.strip()), sep="")
            if shell.onecmd(cmd) is False:
                break
        return 0

    shell.loop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
