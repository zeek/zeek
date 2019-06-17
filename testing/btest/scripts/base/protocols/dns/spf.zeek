# @TEST-EXEC: zeek -b -r $TRACES/dns-spf.pcap %INPUT
# @TEST-EXEC: btest-diff dns.log

@load base/protocols/dns