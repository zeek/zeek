# @TEST-EXEC: zeek -b -r $TRACES/ip6_esp.trace %INPUT >output
# @TEST-EXEC: btest-diff output

# Just check that the event is raised correctly for a packet containing
# ESP extension headers.

event esp_packet(p: pkt_hdr)
	{
	if ( p?$ip6 )
		print p$ip6;
	}
