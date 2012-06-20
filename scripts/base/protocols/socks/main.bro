@load base/frameworks/tunnels
@load ./consts

module SOCKS;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record {
		## Time when the proxy connection was first detected.
		ts:          time    &log;
		uid:         string  &log;
		id:          conn_id &log;
		## Protocol version of SOCKS.
		version:     count   &log;
		## Username for the proxy if extracted from the network.
		user:        string  &log &optional;
		## Server status for the attempt at using the proxy.
		status:      string  &log &optional;
		## Client requested address.  Mutually exclusive with req_name.
		req_h:       addr    &log &optional;
		## Client requested domain name.  Mutually exclusive with req_h.
		req_name:    string  &log &optional;
		## Client requested port.
		req_p:       port    &log &optional;
		## Server bound address. Mutually exclusive with bound_name.
		bound_h:     addr    &log &optional;
		## Server bound domain name. Mutually exclusive with bound_h.
		bound_name:  string  &log &optional;
		## Server bound port.
		bound_p:     port    &log &optional;
	};
	
	## Event that can be handled to access the SOCKS
	## record as it is sent on to the logging framework.
	global log_socks: event(rec: Info);
}

event bro_init() &priority=5
	{
	Log::create_stream(SOCKS::LOG, [$columns=Info, $ev=log_socks]);
	}

redef record connection += {
	socks: SOCKS::Info &optional;
};

# Configure DPD
redef capture_filters += { ["socks"] = "tcp port 1080" };
redef dpd_config += { [ANALYZER_SOCKS] = [$ports = set(1080/tcp)] };
redef likely_server_ports += { 1080/tcp };

function set_session(c: connection, version: count)
	{
	if ( ! c?$socks )
		c$socks = [$ts=network_time(), $id=c$id, $uid=c$uid, $version=version];
	}

event socks_request(c: connection, version: count, request_type: count, 
                    dstaddr: addr, dstname: string, p: port, user: string) &priority=5
	{
	set_session(c, version);
	
	if ( dstaddr != [::] )
		c$socks$req_h = dstaddr;
	if ( dstname != "" )
		c$socks$req_name = dstname;
	c$socks$req_p = p;
	
	# Copy this conn_id and set the orig_p to zero because in the case of SOCKS proxies there will
	# be potentially many source ports since a new proxy connection is established for each 
	# proxied connection.  We treat this as a singular "tunnel".
	local cid = copy(c$id);
	cid$orig_p = 0/tcp;
	Tunnel::register([$cid=cid, $tunnel_type=Tunnel::SOCKS, $payload_proxy=T]);
	}

event socks_reply(c: connection, version: count, reply: count, dstaddr: addr, dstname: string, p: port) &priority=5
	{
	set_session(c, version);
	
	if ( version == 5 )
		c$socks$status = v5_status[reply];
	else if ( version == 4 )
		c$socks$status = v4_status[reply];
	
	if ( dstaddr != [::] )
		c$socks$bound_h = dstaddr;
	if ( dstname != "" )
		c$socks$bound_name = dstname;
	
	c$socks$bound_p = p;
	}

event socks_reply(c: connection, version: count, reply: count, dstaddr: addr, dstname: string, p: port) &priority=-5
	{
	Log::write(SOCKS::LOG, c$socks);
	}