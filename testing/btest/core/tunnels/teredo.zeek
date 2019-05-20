# @TEST-EXEC: zeek -r $TRACES/tunnels/Teredo.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff tunnel.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log

function print_teredo(name: string, outer: connection, inner: teredo_hdr)
	{
	print fmt("%s: %s", name, outer$id);
	print fmt("    ip6: %s", inner$hdr$ip6);
	if ( inner?$auth )
		print fmt("    auth: %s", inner$auth);
	if ( inner?$origin )
		print fmt("    origin: %s", inner$origin);
	}

event teredo_packet(outer: connection, inner: teredo_hdr)
	{
	print_teredo("packet", outer, inner);
	}

event teredo_authentication(outer: connection, inner: teredo_hdr)
	{
	print_teredo("auth", outer, inner);
	}

event teredo_origin_indication(outer: connection, inner: teredo_hdr)
	{
	print_teredo("origin", outer, inner);
	}

event teredo_bubble(outer: connection, inner: teredo_hdr)
	{
	print_teredo("bubble", outer, inner);
	}
