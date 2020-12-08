# Test-case for valid message format:
# @TEST-EXEC: zeek -b -C -r $TRACES/dns-edns-ecs.pcap %INPUT > output
# @TEST-EXEC: btest-diff output

# Test-case for malformed messages:
# @TEST-EXEC: zeek -b -C -r $TRACES/dns-edns-ecs-bad.pcap %INPUT
# @TEST-EXEC: zeek -b -C -r $TRACES/dns-edns-ecs-weirds.pcap %INPUT base/frameworks/notice/weird
# @TEST-EXEC: btest-diff weird.log

@load policy/protocols/dns/auth-addl

event dns_EDNS_ecs(c: connection, msg: dns_msg, opt: dns_edns_ecs) {
	print opt;
}
