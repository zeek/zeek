# @TEST-DOC: Verify that CNAME and A answers are associated with the correct question.
# @TEST-EXEC: zeek -b -r $TRACES/dns-cname-questions.pcap base/protocols/dns
# @TEST-EXEC: btest-diff dns.log
