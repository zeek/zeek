# @TEST-EXEC: zeek -C -r $TRACES/icmp/icmp6-neighbor-solicit.pcap %INPUT > output
# @TEST-EXEC: btest-diff output

event icmp_neighbor_solicitation(c: connection, icmp: icmp_conn, tgt: addr, options: icmp6_nd_options)
	{
	local hdr: raw_pkt_hdr = get_current_packet_header();
	print fmt("%s", hdr);
	}