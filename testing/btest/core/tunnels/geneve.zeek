# @TEST-EXEC: zeek -b -r $TRACES/tunnels/geneve.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff tunnel.log

@load base/frameworks/tunnels
@load base/protocols/conn

event geneve_packet(c: connection, inner: pkt_hdr, vni: count)
	{
	print "geneve_packet", c$id, inner, vni;
	}
