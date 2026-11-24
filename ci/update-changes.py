#!/usr/bin/env python3
"""
Prepend new entries to CHANGES, in the old update-changes format.

The CHANGES file is a version-annotated log of mainline commits, in the
historical format Zeek users are familiar with. Unlike git history, it ships
with source tarballs and other archive downloads that lack a .git directory.
These differences make it worth updating regularly in CI.

Covers mainline commits since the last zeek-bot run, found via the
Changes-Through trailer it commits. Existing entries are never touched, so
CHANGES can be edited by hand.
"""

import argparse
import io
import re
import subprocess
import sys
from pathlib import Path

# Last commit covered by CHANGES before the first bot run.
FIRST_BASE = "ff3c07c88c10ab351d76d332b58d73dd7db683e7"

TRAILER = "Changes-Through"

BOT = "zeek-bot"

SOURCE = Path(__file__).resolve().parent.parent

# GitHub issue references, as matched by update-changes.
ISSUE = re.compile(r"([Ii]ssue|[Gg][Hh]|#)[ _-]?([0-9]+)")


def git(*args):
    return subprocess.run(
        ["git", "-C", str(SOURCE), *args],
        check=True,
        stdout=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
    ).stdout


def version(rev):
    return subprocess.run(
        [
            sys.executable,
            str(SOURCE / "tools/get-version.py"),
            "--source",
            str(SOURCE),
            "--ref",
            rev,
        ],
        check=True,
        stdout=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
    ).stdout.strip()


def parse_log(*args):
    """Yields (hash, parents, date, author, email, message) for each commit."""
    out = git("log", "--format=%x00%H%x01%P%x01%ci%x01%aN%x01%aE%x01%B", *args)
    for rec in out.split("\0")[1:]:
        h, parents, date, author, email, msg = rec.split("\x01", 5)
        yield h, parents.split(), date, author, email, msg.strip()


def format_entry(author, email, msg):
    if email.endswith("@corelight.com"):
        author += ", Corelight"

    if not msg.startswith("GH-"):
        issues = set()
        for line in msg.splitlines():
            if m := ISSUE.search(line):
                issues.add(int(m[2]))
        msg = "".join(f"GH-{i}: " for i in sorted(issues)) + msg

    first, *rest = msg.splitlines()
    lines = [f"  * {first} ({author})"] + [f"    {l}" for l in rest]
    return "\n" + "\n".join(l.rstrip() for l in lines) + "\n"


def generate(base, head, out):
    for h, parents, date, author, email, msg in parse_log(
        "--first-parent", f"{base}..{head}"
    ):
        if len(parents) == 1:
            if author == BOT:
                # Generated docs and CHANGES commits. Listing the latter would
                # also make every run produce a new CHANGES.
                continue
            if not msg:
                continue
            entries = [format_entry(author, email, msg)]
        else:
            entries = [
                format_entry(a, e, m)
                for _, _, _, a, e, m in parse_log(
                    "--no-merges", "--topo-order", f"{h}^1..{h}^2"
                )
                if m
            ]
            if not entries:
                continue

        out.write(f"{version(h)} | {date}\n")
        out.write("".join(entries))
        out.write("\n")


def last_base(head):
    out = git(
        "log",
        "--first-parent",
        "-1",
        f"--grep=^{TRAILER}: ",
        f"--author={BOT}",
        f"--format=%(trailers:key={TRAILER},valueonly)",
        head,
    )
    return out.strip() or FIRST_BASE


def versions(changes):
    """Returns the versions of each entry header in CHANGES bytes."""
    headers = re.findall(rb"^(\S+) \| ", changes, re.MULTILINE)
    return {v.decode(errors="replace") for v in headers}


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--base", help="default: last Changes-Through trailer")
    parser.add_argument("--head", default="HEAD")
    args = parser.parse_args()

    out = io.StringIO()
    generate(args.base or last_base(args.head), args.head, out)
    new = out.getvalue().encode()

    changes = SOURCE / "CHANGES"
    # Bytes: the old entries contain some CRLF line endings.
    old = changes.read_bytes()

    # Each mainline commit has a unique version, so a repeat means a bad base.
    if dups := versions(new) & versions(old):
        sys.exit(f"Already in CHANGES: {', '.join(sorted(dups))}")

    changes.write_bytes(new + old)


if __name__ == "__main__":
    main()
