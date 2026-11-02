# @TEST-DOC: Verify that A and AAAA questions for the same name remain distinct.
# @TEST-EXEC: zeek -b -r $TRACES/dns/dns-duplicate-questions.pcap base/protocols/dns
# @TEST-EXEC: btest-diff dns.log
