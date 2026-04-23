#!/usr/bin/env python3
"""Create a ZIP archive with specified entries.

Usage: create-zip.py <output.zip> <name1> <content1> [<name2> <content2> ...]

Each pair of arguments is a filename and its content. Escape sequences
like \\n in content are interpreted.
"""

import sys
import zipfile


def main():
    if len(sys.argv) < 4 or (len(sys.argv) - 2) % 2 != 0:
        print(
            f"Usage: {sys.argv[0]} <output.zip> <name> <content> [<name> <content> ...]",
            file=sys.stderr,
        )
        sys.exit(1)

    output_path = sys.argv[1]
    entries = []
    for i in range(2, len(sys.argv), 2):
        name = sys.argv[i]
        content = sys.argv[i + 1].encode().decode("unicode_escape")
        entries.append((name, content))

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries:
            zf.writestr(name, content)


if __name__ == "__main__":
    main()
