#! /bin/sh

find ../testing/btest -type f |
    egrep -v 'Baseline|\.tmp' |
    egrep '\.(zeek|test)$' |
    sort |
    xargs egrep -l '^[ 	]*(event|print)' |
    xargs egrep -lc 'REQUIRES.*CPP.*((!=.*1)|(==.*0))' |
    grep ':0$' |
    sed 's,:0,,'
