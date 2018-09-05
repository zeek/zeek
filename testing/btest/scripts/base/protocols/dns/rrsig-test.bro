# This tests the case where the queries and responses include DNSSEC RRs.
#
# @TEST-EXEC: bro -r $TRACES/rrsig.trace 
# @TEST-EXEC: btest-diff dns.log
