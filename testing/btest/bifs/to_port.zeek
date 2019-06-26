#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print to_port("123/tcp");
	print to_port("123/udp");
	print to_port("123/icmp");
	print to_port("0/tcp");
	print to_port("0/udp");
	print to_port("0/icmp");
	print to_port("not a port");

	local a: transport_proto = tcp;
	local b: transport_proto = udp;
	local c: transport_proto = icmp;
	print count_to_port(256, a);
	print count_to_port(256, b);
	print count_to_port(256, c);
	}
