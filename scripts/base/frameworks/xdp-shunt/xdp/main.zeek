module XDP;

export {
	## Reconnects to an already-existing XDP shunting program.
	## This allows Zeek to add and remove from the map.
	##
	## Reconnecting is preferable to start_shunt in all but standalone
	## instances of Zeek.
	##
	## Returns: An opaque value representing the now-attached BPF program
	##
	## .. zeek:see:: start_shunt
	global reconnect: function(): opaque of XDP::Program;

	## Disconnects an XDP program and invalidates what was passed in.
	global disconnect: function(xdp_prog: opaque of XDP::Program);

	## Begins shunting with XDP by loading the XDP program and necessary BPF maps.
	##
	## Returns: An opaque value representing the now-attached BPF program
	##
	## .. zeek:see:: end_shunt
	global start_shunt: function(options: XDP::ShuntOptions): opaque of
	    XDP::Program;

	## Stops the XDP shunting program.
	##
	## Returns: Whether the operation succeeded
	##
	## .. zeek:see:: start_shunt
	global end_shunt: function(xdp_prog: opaque of XDP::Program): bool;

	## Transforms a conn_id into its canonical_id representation
	## by sorting the IPs and ports as the shunting map does.
	global conn_id_to_canonical: function(cid: conn_id): XDP::canonical_id;
}
function reconnect(): opaque of XDP::Program
	{
	return _reconnect_shunt();
	}

function disconnect(xdp_prog: opaque of XDP::Program)
	{
	return _disconnect_shunt();
	}

function start_shunt(options: XDP::ShuntOptions): opaque of XDP::Program
	{
	return _start_shunt(options);
	}

function end_shunt(xdp_prog: opaque of XDP::Program): bool
	{
	return _end_shunt(xdp_prog);
	}

function conn_id_to_canonical(cid: conn_id): XDP::canonical_id
	{
	# Users can add vlans if they wish.
	local can_id = XDP::canonical_id($ip1=cid$orig_h, $ip1_port=cid$orig_p,
	    $ip2=cid$resp_h, $ip2_port=cid$resp_p, $proto=cid$proto, );

	# Order them so ip2 is the higher one.
	if ( can_id$ip1 > can_id$ip2
	    || ( ( can_id$ip1 == can_id$ip2 ) && can_id$ip1_port > can_id$ip2_port ) )
		{
		# Flip the ips and ports
		local tmp_a = can_id$ip1;
		local tmp_p = can_id$ip1_port;
		can_id$ip1 = can_id$ip2;
		can_id$ip1_port = can_id$ip2_port;
		can_id$ip2 = tmp_a;
		can_id$ip2_port = tmp_p;
		}

	return can_id;
	}
