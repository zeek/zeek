# @TEST-EXEC: bro -C -r $TRACES/wikipedia.trace %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff conn.log

redef enum PcapFilterID += { A, B };

global cnt = 0;

event new_packet(c: connection, p: pkt_hdr)
	{
	++cnt;

	print cnt, c$id;
	
	if ( cnt == 1 )
		if ( ! install_pcap_filter(A) )
			print "error 3";

	if ( cnt == 2 )
		if ( ! install_pcap_filter(B) )
			print "error 4";
	}

event bro_init()
	{
	if ( ! precompile_pcap_filter(A, "port 80") )
		print "error 1";
	
	if ( ! precompile_pcap_filter(B, "port 53") )
		print "error 2";
	}

