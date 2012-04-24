module Tunnels;

export {
	redef enum Log::ID += { LOG };
	
	type Action: enum {
		DISCOVER,
		CLOSE,
	};
	
	type Info: record {
		ts:          time    &log;
		uid:         string  &log &optional;
		id:          conn_id &log;
		action:      Action  &log;
		tunnel_type: string  &log;
		user:        string  &log &optional;
	};
	
	global register: function(c: connection, tunnel_type: string);
	
	global active: table[conn_id] of Tunnels::Info = table();
}

event bro_init() &priority=5
	{
	Log::create_stream(Tunnels::LOG, [$columns=Info]);
	}

function register(c: connection, tunnel_type: string)
	{
	local tunnel: Info;
	tunnel$ts = network_time();
	tunnel$uid = c$uid;
	tunnel$id = c$id;
	tunnel$action = DISCOVER;
	tunnel$tunnel_type = tunnel_type;
	
	active[c$id] = tunnel;
	Log::write(LOG, tunnel);
	}
	
event connection_state_remove(c: connection) &priority=-5
	{
	if ( c$id in active )
		{
		local tunnel = active[c$id];
		tunnel$action=CLOSE;
		Log::write(LOG, tunnel);
		
		delete active[c$id];
		}
	}