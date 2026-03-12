# This tests the case where the DNS server responded with zero RRs.
#
# @TEST-EXEC: zeek -b -r $TRACES/dns-txt-multiple.pcap base/protocols/dns
# @TEST-EXEC: btest-diff dns.log
