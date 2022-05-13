#! /bin/sh

find ../testing/btest -type f |
    egrep -v 'Baseline|\.tmp' |
    egrep '\.(zeek|test)$' |
    sort
