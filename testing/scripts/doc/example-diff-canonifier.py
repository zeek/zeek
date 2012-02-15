#!/usr/bin/python

import sys
import re

# MutableVal derivatives (e.g. sets/tables) don't always generate the same
# ordering in the reST documentation, so just don't bother diffing
# the places where example.bro uses them.

RE1 = "\d*/tcp"
RE2 = "tcp port \d*"

for line in sys.stdin.readlines():
    if re.search(RE1, line) is None and re.search(RE2, line) is None:
        print line
