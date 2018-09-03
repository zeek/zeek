# This tests the case where the queries and responses include DNSSEC RRs.
#
# @TEST-EXEC: bro -r $TRACES/dnssec.trace -C
# @TEST-EXEC: btest-diff dns.log
