##! This script handles the tracking/logging of tunnels (e.g. Teredo,
##! AYIYA, or IP-in-IP such as 6to4 where "IP" is either IPv4 or IPv6).
##!
##! For any connection that occurs over a tunnel, information about its
##! encapsulating tunnels is also found in the *tunnel* field of
##! :bro:type:`connection`.

module Tunnel;

export {
	## The tunnel logging stream identifier.
	redef enum Log::ID += { LOG };

	## Types of interesting activity that can occur with a tunnel.
	type Action: enum {
		## A new tunnel (encapsulating "connection") has been seen.
		DISCOVER,
		## A tunnel connection has closed.
		CLOSE,
		## No new connections over a tunnel happened in the amount of
		## time indicated by :bro:see:`Tunnel::expiration_interval`.
		EXPIRE,
	};

	## The record type which contains column fields of the tunnel log.
	type Info: record {
		## Time at which some tunnel activity occurred.
		ts:          time         &log;
		## The unique identifier for the tunnel, which may correspond
		## to a :bro:type:`connection`'s *uid* field for non-IP-in-IP tunnels.
		## This is optional because there could be numerous connections
		## for payload proxies like SOCKS but we should treat it as a
		## single tunnel.
		uid:         string       &log &optional;
		## The tunnel "connection" 4-tuple of endpoint addresses/ports.
		## For an IP tunnel, the ports will be 0.
		id:          conn_id      &log;
		## The type of tunnel.
		tunnel_type: Tunnel::Type &log;
		## The type of activity that occurred.
		action:      Action       &log;
	};

	## Logs all tunnels in an encapsulation chain with action
	## :bro:see:`Tunnel::DISCOVER` that aren't already in the
	## :bro:id:`Tunnel::active` table and adds them if not.
	global register_all: function(ecv: EncapsulatingConnVector);

	## Logs a single tunnel "connection" with action
	## :bro:see:`Tunnel::DISCOVER` if it's not already in the
	## :bro:id:`Tunnel::active` table and adds it if not.
	global register: function(ec: EncapsulatingConn);

	## Logs a single tunnel "connection" with action
	## :bro:see:`Tunnel::EXPIRE` and removes it from the
	## :bro:id:`Tunnel::active` table.
	##
	## t: A table of tunnels.
	##
	## idx: The index of the tunnel table corresponding to the tunnel to expire.
	##
	## Returns: 0secs, which when this function is used as an
	##          :bro:attr:`&expire_func`, indicates to remove the element at
	##          *idx* immediately.
	global expire: function(t: table[conn_id] of Info, idx: conn_id): interval;

	## Removes a single tunnel from the :bro:id:`Tunnel::active` table
	## and logs the closing/expiration of the tunnel.
	##
	## tunnel: The tunnel which has closed or expired.
	##
	## action: The specific reason for the tunnel ending.
	global close: function(tunnel: Info, action: Action);

	## The amount of time a tunnel is not used in establishment of new
	## connections before it is considered inactive/expired.
	const expiration_interval = 1hrs &redef;

	## Currently active tunnels.  That is, tunnels for which new,
	## encapsulated connections have been seen in the interval indicated by
	## :bro:see:`Tunnel::expiration_interval`.
	global active: table[conn_id] of Info = table() &read_expire=expiration_interval &expire_func=expire;
}

const ayiya_ports = { 5072/udp };
const teredo_ports = { 3544/udp };
const gtpv1_ports = { 2152/udp, 2123/udp };
redef likely_server_ports += { ayiya_ports, teredo_ports, gtpv1_ports };

event bro_init() &priority=5
	{
	Log::create_stream(Tunnel::LOG, [$columns=Info]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_AYIYA, ayiya_ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_TEREDO, teredo_ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_GTPV1, gtpv1_ports);
	}

function register_all(ecv: EncapsulatingConnVector)
	{
	for ( i in ecv )
		register(ecv[i]);
	}

function register(ec: EncapsulatingConn)
	{
	if ( ec$cid !in active )
		{
		local tunnel: Info;
		tunnel$ts = network_time();
		if ( ec?$uid )
			tunnel$uid = ec$uid;
		tunnel$id = ec$cid;
		tunnel$action = DISCOVER;
		tunnel$tunnel_type = ec$tunnel_type;
		active[ec$cid] = tunnel;
		Log::write(LOG, tunnel);
		}
	}

function close(tunnel: Info, action: Action)
	{
	tunnel$action = action;
	tunnel$ts = network_time();
	Log::write(LOG, tunnel);
	delete active[tunnel$id];
	}

function expire(t: table[conn_id] of Info, idx: conn_id): interval
	{
	close(t[idx], EXPIRE);
	return 0secs;
	}

event new_connection(c: connection) &priority=5
	{
	if ( c?$tunnel )
		register_all(c$tunnel);
	}

event tunnel_changed(c: connection, e: EncapsulatingConnVector) &priority=5
	{
	register_all(e);
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( c$id in active )
		close(active[c$id], CLOSE);
	}
