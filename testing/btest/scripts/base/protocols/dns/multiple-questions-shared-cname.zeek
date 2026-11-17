# @TEST-DOC: Verify that A and AAAA questions sharing a CNAME receive their corresponding answers.
# @TEST-EXEC: zeek -b -r $TRACES/dns/dns-shared-cname.pcap base/protocols/dns
# @TEST-EXEC: btest-diff dns.log
