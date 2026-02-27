##! This script is meant to be roughly equivalent to:
##! https://github.com/JustinAzoff/bro-react/blob/master/conn-bulk.bro

@load base/protocols/conn
@load xdp

module XDP::Shunt::Bulk;

export {
	## Number of bytes transferred before marking a connection as bulk.
	const size_threshold = 1048576 &redef; # 1MB

	## Max number of times to check whether a connection's size exceeds the
	## size threshold.
	const max_poll_count = 30 &redef;

	## The max number of shunted connections, dictates the BPF map size.
	const max_shunted_conns = 131072 &redef;

	## How frequently to check if the size threshold is exceeded.
	const poll_interval = 1sec &redef;

	## If we should even look at shunting this connection. Break if we should
	## not start polling to shunt it.
	global bulk_shunt_policy: hook(cid: conn_id) &redef;
}

function conn_callback(c: connection, cnt: count): interval
	{
	local stats = XDP::Shunt::ConnID::shunt_stats(c$id);
	if ( stats$present )
		return -1sec; # Failsafe

	# Shunt it if over threshold
	if ( c$orig$size > size_threshold || c$resp$size > size_threshold )
		{
		XDP::Shunt::ConnID::shunt(c$id);
		return -1sec;
		}

	if ( cnt >= max_poll_count )
		return -1sec;

	return poll_interval;
	}

event new_connection(c: connection) &priority=-5
	{
	if ( hook bulk_shunt_policy(c$id) )
		ConnPolling::watch(c, conn_callback, 0, 0secs);
	}
