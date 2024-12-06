#!/usr/bin/env python3

import sys
import re

exit_code = 0

pat1 = re.compile(r"See the file \"COPYING\" in the main distribution directory for copyright.")

# This is the copyright line used within Spicy plugin and popular in
# Spicy analyzers.
pat2 = re.compile(r"Copyright \(c\) 2... by the Zeek Project. See COPYING for details.")


def match_line(line):
    for pat in [pat1, pat2]:
        m = pat.search(line)
        if m is not None:
            return True

    return False


for f in sys.argv[1:]:
    has_license_header = False
    with open(f) as fp:
        for line in fp:
            line = line.strip()
            if has_license_header := match_line(line):
                break

    if not has_license_header:
        print(f"{f}:does not seem to contain a license header", file=sys.stderr)
        exit_code = 1

sys.exit(exit_code)
