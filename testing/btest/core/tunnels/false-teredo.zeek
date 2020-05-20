# @TEST-EXEC: zeek -r $TRACES/tunnels/false-teredo.pcap %INPUT >output
# @TEST-EXEC: test ! -e weird.log
# @TEST-EXEC: test ! -e dpd.log

# In the first case, there isn't any weird or protocol violation logged
# since the teredo analyzer recognizes that the DNS analyzer has confirmed
# the protocol and yields.

# In the second case, there are weirds since the teredo analyzer decapsulates
# despite the presence of the confirmed DNS analyzer and the resulting
# inner packets are malformed (no surprise there).  There's also no dpd.log
# since the teredo analyzer doesn't confirm until it's seen a valid teredo
# encapsulation in both directions and protocol violations aren't logged
# until there's been a confirmation.

# In either case, the analyzer doesn't, by default, get disabled as a result
# of the protocol violations.

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
