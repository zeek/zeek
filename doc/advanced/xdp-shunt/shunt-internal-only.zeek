@load frameworks/xdp-shunt

export {
	global internal_nets: set[subnet] = set(192.168.0.0 / 16, );
}

# Tell Zeek to start a new XDP program, not reconnect
redef XDP::start_new_xdp = T;

hook XDP::shunting(c: connection)
	{
	if ( c$id$orig_h in internal_nets || c$id$resp_h in internal_nets )
		# Return normally: we want to shunt the connection
		return;

	# Default: Do not shunt the connection
	print fmt("Vetoing shunt for: %s", c$id);
	break;
	}

event XDP::Shunt::ConnID::connection_shunting_started(cid: conn_id)
	{
	print fmt("Connection shunted: %s", cid);
	}
