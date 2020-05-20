# @TEST-EXEC: zeek -b -r $TRACES/tunnels/ping6-in-ipv4.pcap %INPUT >>output 2>&1
# @TEST-EXEC: btest-diff output

event new_connection(c: connection)
	{
	if ( c?$tunnel )
		{
		print "new_connection: tunnel";
		print fmt("    conn_id: %s", c$id);
		print fmt("    encap: %s", c$tunnel);
		}
	else
		{
		print "new_connection: no tunnel";
		}
	}

event tunnel_changed(c: connection, e: EncapsulatingConnVector)
	{
	print "tunnel_changed:";
	print fmt("    conn_id: %s", c$id);
	if ( c?$tunnel )
		print fmt("    old: %s", c$tunnel);
	print fmt("    new: %s", e);
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	print "NEW_PACKET:";
	print fmt("    %s", c$id);
	if ( c?$tunnel )
		print fmt("    %s", c$tunnel);
	}
