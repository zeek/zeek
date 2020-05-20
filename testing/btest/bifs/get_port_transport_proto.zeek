#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = 123/tcp;
	local b = 123/udp;
	local c = 123/icmp;
	print get_port_transport_proto(a);
	print get_port_transport_proto(b);
	print get_port_transport_proto(c);
	}
