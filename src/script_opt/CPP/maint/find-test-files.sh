#! /bin/sh

find ../testing/btest -type f |
    grep -E -v 'Baseline|\.tmp|__load__' |
    grep -E '\.(zeek|test)$' |
    sort |
    xargs grep -E -l '^[ 	]*(event|print)' |
    xargs grep -E -c 'REQUIRES.*CPP.*((!=.*1)|(==.*0))' |
    grep ':0$' |
    sed 's,:0,,'
