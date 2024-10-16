#! /bin/sh

find ../testing/btest -type f |
    xargs grep -E -l '@TEST' |
    xargs grep -E -l '^[ 	]*(event|print)' |
    xargs grep -E -c 'REQUIRES.*CPP.*((!=.*1)|(==.*0))' |
    grep ':0$' |
    sed 's,:0,,' |
    sort
