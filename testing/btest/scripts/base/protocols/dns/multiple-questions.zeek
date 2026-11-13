# Regression test for DNS messages containing multiple questions.
# Related issue: zeek/zeek#5037
#
# @TEST-EXEC: zeek -b -r $TRACES/dns/dns-three-questions-one-answer.pcap base/protocols/dns
# @TEST-EXEC: btest-diff dns.log
