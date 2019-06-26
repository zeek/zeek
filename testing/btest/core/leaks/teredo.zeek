# Needs perftools support.
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-GROUP: leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -r $TRACES/tunnels/Teredo.pcap %INPUT >output
# @TEST-EXEC: btest-bg-wait 60

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
