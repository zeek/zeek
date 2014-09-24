# @TEST-EXEC: bro -r $TRACES/workshop_2011_browse.trace -w dump
# @TEST-EXEC: hexdump -C $TRACES/workshop_2011_browse.trace >1
# @TEST-EXEC: hexdump -C dump >2
# @TEST-EXEC: sdiff -s 1 2 >output || true
# @TEST-EXEC: btest-diff output
