# This tests the case where the DNS server responded with zero RRs.
#
# @TEST-EXEC: zeek -b -r $TRACES/dns-two-responses.trace base/protocols/dns
# @TEST-EXEC: btest-diff dns.log
