#! /bin/sh

find ../testing/btest -type f |
    grep -v '\.tmp/' |
    xargs grep -E -l '@TEST' |
    xargs grep -E -l '^[ 	]*(event|print)' |
    xargs grep -E -c '(REQUIRES.*CPP.*((!=.*1)|(==.*0)))|@TEST-START-NEXT' |
    grep ':0$' |
    sed 's,:0,,' |
    sort
