# @TEST-DOC: Regression test for #4845, get_current_packet_header() for a fragmented SYN packet
#
# @TEST-EXEC: zeek -b -C -r $TRACES/ipv4/fragmented-syn.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

event connection_SYN_packet(c: connection, pkt: SYN_packet)
	{
	local hdr: raw_pkt_hdr = get_current_packet_header();
	print fmt("%s", hdr);
	}
