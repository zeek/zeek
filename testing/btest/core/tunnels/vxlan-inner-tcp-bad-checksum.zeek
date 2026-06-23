# @TEST-DOC: Verify VXLAN with an inner TCP SYN with bad checksum doesn't tickle UBSAN nullptr deref.
#
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/vxlan-inner-tcp-bad-checksum.pcap %INPUT >out
#
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log

@load base/frameworks/tunnels
@load base/protocols/conn
@load base/frameworks/notice/weird

event vxlan_packet(c: connection, inner: pkt_hdr, vni: count)
	{
	print "vxlan_packet", c$id, inner, vni;
	}
