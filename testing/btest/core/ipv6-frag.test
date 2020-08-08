# @TEST-EXEC: zeek -b -r $TRACES/ipv6-fragmented-dns.trace %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff dns.log

@load base/protocols/dns

event new_packet(c: connection, p: pkt_hdr)
	{
	if ( p?$ip6 && p?$ udp )
		print fmt("ip6=%s, udp = %s", p$ip6, p$udp);
	}
