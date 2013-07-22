# This tests the case where the DNS server responded with zero RRs.
#
# @TEST-EXEC: bro -r $TRACES/dns-two-responses.trace
# @TEST-EXEC: btest-diff dns.log
# @TEST-EXEC: btest-diff weird.log