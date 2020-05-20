# This tests the case where the DNS server responded with zero RRs.
#
# @TEST-EXEC: zeek -r $TRACES/dns-txt-multiple.trace
# @TEST-EXEC: btest-diff dns.log
