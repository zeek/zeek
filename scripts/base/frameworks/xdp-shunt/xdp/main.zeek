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
	global reconnect: function(options: XDP::ShuntOptions): bool;

	## Disconnects the XDP program.
	global disconnect: function();

	## Begins shunting with XDP by loading the XDP program and necessary BPF maps.
	##
	## Returns: An opaque value representing the now-attached BPF program
	##
	## .. zeek:see:: end_shunt
	global start_shunt: function(options: XDP::ShuntOptions): bool;

	## Stops the XDP shunting program.
	##
	## Returns: Whether the operation succeeded
	##
	## .. zeek:see:: start_shunt
	global end_shunt: function(): bool;

	## Transforms a conn_id into its canonical_id representation
	## by sorting the IPs and ports as the shunting map does.
	global conn_id_to_canonical: function(cid: conn_id): XDP::canonical_id;

	global xdp_prog: opaque of XDP::Program;
}

function reconnect(options: XDP::ShuntOptions): bool
	{
	xdp_prog = _reconnect_shunt(options);
	# TODO: if it fails this should probably return F
	return T;
	}

function disconnect()
	{
	_disconnect_shunt(xdp_prog);
	}

function start_shunt(options: XDP::ShuntOptions): bool
	{
	xdp_prog = _start_shunt(options);
	# TODO: if it fails this should probably return F
	return T;
	}

function end_shunt(): bool
	{
	return _end_shunt(xdp_prog);
	}

function conn_id_to_canonical(cid: conn_id): XDP::canonical_id
	{
	return _conn_id_to_canonical(cid);
	}
