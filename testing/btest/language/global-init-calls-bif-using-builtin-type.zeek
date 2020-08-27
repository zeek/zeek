# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

# This test isn't specifically testing the PacketFilter functionality, rather
# that a global variable can be initialized using a BIF call and that BIF call
# can make use of some global type pointers to builtin types/aliases.

@load base/frameworks/packet-filter
redef PacketFilter::restricted_filter = PacketFilter::port_to_bpf(80/tcp);

event zeek_init()
	{
	print PacketFilter::restricted_filter;
	}
