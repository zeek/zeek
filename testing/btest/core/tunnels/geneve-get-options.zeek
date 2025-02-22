# @TEST-EXEC: zeek -C -b -r $TRACES/tunnels/geneve-many-options.pcap %INPUT >>out
# @TEST-EXEC: zeek -C -b -r $TRACES/tunnels/geneve-tagged-udp-packet.pcap %INPUT >>out
# @TEST-EXEC: btest-diff out

@load base/frameworks/tunnels
@load base/protocols/conn


event new_connection(c: connection)
	{
	if ( ! c?$tunnel )
		return;

	print "new_connection", c$uid, split_string(packet_source()$path, /\//)[-1];

	for ( _, layer in PacketAnalyzer::Geneve::get_options() )
		for ( _, opt in layer )
			print "opt", opt;

	}
