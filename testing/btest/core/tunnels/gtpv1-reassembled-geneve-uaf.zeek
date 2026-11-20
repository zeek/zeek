# @TEST-DOC: Regression test for use-after-free when calling PacketAnalyzer::Geneve::get_options() for GENEVE over fragmented tunneled IP packets.
#
# @TEST-EXEC: zeek -C -b -r $TRACES/tunnels/gtpv1-reassembled-geneve-uaf.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m uid service history tunnel_parents conn.log

@load base/protocols/conn

event new_connection(c: connection)
	{
	print "new_connection", c$uid;

	for ( _, layer in PacketAnalyzer::Geneve::get_options() )
		for ( _, opt in layer )
			print "opt", opt;
	}
