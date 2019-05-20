# @TEST-REQUIRES: which hexdump
# @TEST-EXEC: zeek -r $TRACES/workshop_2011_browse.trace -w dump
# @TEST-EXEC: hexdump -C $TRACES/workshop_2011_browse.trace >1
# @TEST-EXEC: hexdump -C dump >2
# @TEST-EXEC: diff 1 2 >output || true

# Note that we're diff'ing the diff because there is an expected
# difference in the pcaps: namely, the snaplen setting stored in the
# global pcap header.
# @TEST-EXEC: btest-diff output
