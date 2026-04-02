# @TEST-EXEC: zeek -C -r $TRACES/dns/dns_notify2.pcap
# @TEST-EXEC: btest-diff dns.log
