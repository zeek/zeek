# @TEST-DOC: Test TCP::raw_option_list BiF
#
# @TEST-EXEC: zeek -C -r $TRACES/tls/tls1_1.pcap %INPUT
# Ensure correct results when run against non-TCP-traffic
# @TEST-EXEC: zeek -C -r $TRACES/tls/dtls1_0.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

global packet_number: count = 0;

event connection_SYN_packet(c: connection, pkt: SYN_packet)
	{
	print c$id, TCP::raw_option_list();
	}

event raw_packet(p: raw_pkt_hdr)
	{
	++packet_number;
	if ( packet_number == 4 )
		print p, TCP::raw_option_list();
	}

# @TEST-START-NEXT

event connection_SYN_packet(c: connection, pkt: SYN_packet)
	{
	print c$id, TCP::raw_option_list(F);
	}
