##! This script is meant to be functionally equivalent to:
##! https://github.com/JustinAzoff/bro-react/blob/master/conn-bulk.bro

@load base/protocols/conn
@load xdp
@load xdp/conn_id

module XDP::Bulk;

export {
	## Number of bytes transferred before marking a connection as bulk.
	const size_threshold = 1048576 &redef; # 1MB

	## Max number of times to check whether a connection's size exceeds the
	## size threshold.
	const max_poll_count = 30 &redef;

	## The XDP mode when starting the XDP program.
	const xdp_mode = XDP::UNSPEC &redef;

	## The max number of shunted connections, dictates the BPF map size.
	const max_shunted_conns = 131072 &redef;

	## How frequently to check if the size threshold is exceeded.
	const poll_interval = 1sec &redef;

	## How frequently to check if the connection should be unshunted.
	const unshunt_poll_interval = 1sec &redef;

	## How long without a packet that the connection should unshunt.
	const inactive_unshunt = 1min &redef;

	global shunt_policy: hook(cid: conn_id) &redef;
}

global xdp_prog: opaque of XDP::Program;

function conn_callback(c: connection, cnt: count): interval
	{
	local stats = XDP::ShuntConnID::shunt_stats(xdp_prog, c$id);
	if ( stats$present )
		{
		# This connection is shunted
		local timed_out = stats?$timestamp
		    && stats$timestamp + inactive_unshunt <= current_time();
		if ( timed_out || stats$fin > 0 || stats$rst > 0 )
			{
			XDP::ShuntConnID::unshunt(xdp_prog, c$id);
			return -1sec;
			}

		return unshunt_poll_interval;
		}
	if ( c$orig$size > size_threshold || c$resp$size > size_threshold )
		{
		if ( XDP::ShuntConnID::shunt_stats(xdp_prog, c$id)$present )
			return -1sec;

		XDP::ShuntConnID::shunt(xdp_prog, c$id);
		return unshunt_poll_interval;
		}

	if ( cnt >= max_poll_count )
		return -1sec;

	return poll_interval;
	}

event new_connection(c: connection) &priority=-5
	{
	if ( hook shunt_policy(c$id) )
		ConnPolling::watch(c, conn_callback, 0, 0secs);
	}

event zeek_init()
	{
	local opts: XDP::ShuntOptions = [
		$attach_mode=xdp_mode,
		$conn_id_map_max_size=max_shunted_conns,
		$ip_pair_map_max_size=1, # Effectively 0
	];
	xdp_prog = XDP::start_shunt(opts);
	}

event zeek_done()
	{
	XDP::end_shunt(xdp_prog);
	}
