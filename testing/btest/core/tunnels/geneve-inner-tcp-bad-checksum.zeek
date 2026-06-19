# @TEST-DOC: Verify Geneve with an inner TCP SYN with bad checksum doesn't tickle UBSAN nullptr deref.
#
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/geneve-inner-tcp-bad-checksum.pcap %INPUT >out
#
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log

@load base/frameworks/tunnels
@load base/protocols/conn
@load base/frameworks/notice/weird

event geneve_packet(c: connection, inner: pkt_hdr, vni: count)
	{
	print "geneve_packet", c$id, inner, vni;
	}
