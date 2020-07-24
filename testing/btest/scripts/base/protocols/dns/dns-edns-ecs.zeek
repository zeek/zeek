# @TEST-EXEC: zeek -C -r $TRACES/dns-edns-ecs.pcap %INPUT > output
# @TEST-EXEC: btest-diff output

@load policy/protocols/dns/auth-addl

event dns_EDNS_ecs(c: connection, msg: dns_msg, opt: dns_edns_ecs) {
	print opt;
}