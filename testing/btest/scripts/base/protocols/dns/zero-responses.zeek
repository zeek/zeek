# This tests the case where the DNS server responded with zero RRs.
#
# @TEST-EXEC: zeek -b -r $TRACES/dns-zero-RRs.trace base/protocols/dns
# @TEST-EXEC: btest-diff dns.log
