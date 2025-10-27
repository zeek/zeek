module XDP;

export {
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
}

function start_shunt(options: XDP::ShuntOptions): opaque of XDP::Program
	{
	return _start_shunt(options);
	}

function end_shunt(xdp_prog: opaque of XDP::Program): bool
	{
	return _end_shunt(xdp_prog);
	}
