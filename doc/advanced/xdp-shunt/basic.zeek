@load frameworks/xdp-shunt

redef XDP::start_new_xdp = T;

# Print each connection when it is shunted and unshunted, for demonstration.
event XDP::Shunt::ConnID::unshunted_conn(cid: conn_id, stats: XDP::ShuntedStats)
	{
	assert stats$present;
	print fmt("Unshunted connection from %s:%d<->%s:%d. Transmitted %d bytes and %d packets.",
	    cid$orig_h, cid$orig_p, cid$resp_h, cid$resp_p, stats$bytes_from_1 +
	    stats$bytes_from_2, stats$packets_from_1 + stats$packets_from_2);

	if ( stats?$timestamp )
		print fmt("Last packet was at %s.", stats$timestamp);
	}

event XDP::Shunt::ConnID::connection_shunting_started(c: connection)
	{
	print fmt("Shunted connection from %s:%d<->%s:%d", c$id$orig_h, c$id$orig_p,
	    c$id$resp_h, c$id$resp_p);
	}
