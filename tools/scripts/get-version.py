#!/usr/bin/env python3

import argparse
import re
import subprocess
from pathlib import Path

DESCRIPTION = re.compile(
    r"^v(?P<base>\d+\.\d+\.\d+(?:-(?:dev|rc\d+))?)"
    r"-(?P<count>\d+)-g[0-9a-f]+$"
)


def zeek_version(source: Path, ref: str) -> str:
    # Release archives have no Git metadata, but carry the version determined
    # when the archive was assembled.
    if not (source / ".git").exists():
        try:
            return (source / "VERSION").read_text().splitlines()[0]
        except (FileNotFoundError, IndexError):
            raise SystemExit(
                "Cannot determine Zeek version: no Git metadata or VERSION file"
            )

    try:
        description = subprocess.check_output(
            [
                "git",
                "-C",
                str(source),
                "describe",
                "--tags",
                "--long",
                "--match",
                "v[0-9]*",
                ref,
            ],
            text=True,
        ).strip()
    except subprocess.CalledProcessError:
        raise SystemExit(
            "Cannot determine Zeek version: fetch the version tags and history"
        )

    match = DESCRIPTION.fullmatch(description)
    if not match:
        raise SystemExit(f"Unrecognized version tag: {description}")

    base = match["base"]
    count = int(match["count"])
    if count == 0:
        return base

    return f"{base}.{count}" if "-" in base else f"{base}-{count}"


parser = argparse.ArgumentParser()
parser.add_argument("--source", type=Path, default=Path("."))
parser.add_argument("--ref", default="HEAD")
parser.add_argument("-o", "--output", default="-", type=argparse.FileType("w"))
args = parser.parse_args()

version = zeek_version(args.source, args.ref)
args.output.write(version + "\n")
