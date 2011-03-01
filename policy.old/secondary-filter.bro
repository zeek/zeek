# $Id: secondary-filter.bro 6022 2008-07-25 19:15:00Z vern $

# Examples of using the secondary-filter matching path.

event rst_syn_fin_flag(filter: string, pkt: pkt_hdr)
	{
	print "rst_syn_fin_flag()";
	print fmt("    %s:%s -> %s:%s", pkt$ip$src, pkt$tcp$sport,
			pkt$ip$dst, pkt$tcp$dport);
	}

event a_udp_event(filter: string, pkt: pkt_hdr)
	{
	print "a_udp_event()";
	print fmt("    %s:%s -> %s:%s", pkt$ip$src, pkt$udp$sport,
			pkt$ip$dst, pkt$udp$dport);
	}

event a_tcp_event(filter: string, pkt: pkt_hdr)
	{
	print "a_tcp_event()";
	print fmt("    %s:%s -> %s:%s", pkt$ip$src, pkt$tcp$sport,
			pkt$ip$dst, pkt$tcp$dport);
	}

event sampled_1_in_1024_packet(filter: string, pkt: pkt_hdr)
	{
	print "sampled packet:";
	print "ip", pkt$ip;

	if ( pkt?$tcp )
		print "tcp", pkt$tcp;
	if ( pkt?$udp )
		print "udp", pkt$udp;
	if ( pkt?$icmp )
		print "icmp", pkt$icmp;
	}

redef secondary_filters += {
	["tcp[13] & 7 != 0"] = rst_syn_fin_flag,
	["udp"] = a_udp_event,
	["tcp"] = a_tcp_event,
	["ip[10:2] & 0xffc == 0x398"] = sampled_1_in_1024_packet,
};
