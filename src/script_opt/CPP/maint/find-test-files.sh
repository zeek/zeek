#! /bin/sh

find ../testing/btest -type f |
    grep -E -v 'Baseline|\.tmp' |
    grep -E '\.(zeek|test)$' |
    sort |
    xargs grep -E -l '^[ 	]*(event|print)' |
    xargs grep -E -lc 'REQUIRES.*CPP.*((!=.*1)|(==.*0))' |
    grep ':0$' |
    sed 's,:0,,'
