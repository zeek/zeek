# @TEST-EXEC: zeek -b -r $TRACES/tunnels/gtp/gtp_ext_header.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/frameworks/tunnels

event gtpv1_message(c: connection, hdr: gtpv1_hdr)
	{
	print "gtpv1_message", c$id;
	print hdr;
	}
