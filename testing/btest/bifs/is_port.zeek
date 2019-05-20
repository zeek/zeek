#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = 123/tcp;
	local b = 123/udp;
	local c = 123/icmp;

	print is_tcp_port(a);
	print is_tcp_port(b);
	print is_tcp_port(c);

	print is_udp_port(a);
	print is_udp_port(b);
	print is_udp_port(c);

	print is_icmp_port(a);
	print is_icmp_port(b);
	print is_icmp_port(c);
	}
