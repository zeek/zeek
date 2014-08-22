# This tests the case where the DNS server responded with zero RRs.
#
# @TEST-EXEC: bro -r $TRACES/dns-txt-multiple.trace
# @TEST-EXEC: btest-diff dns.log
