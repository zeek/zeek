@load base/frameworks/tunnels

module SOCKS;

export {
	type RequestType: enum {
		CONNECTION = 1,
		PORT       = 2,
	};
}

event socks_request(c: connection, request_type: count, dstaddr: addr, dstname: string, p: port, user: string)
	{
	Tunnels::register(c, "SOCKS");
	}

#
#global output = open_log_file("socks");
#
#type socks_conn: record {
#	id: conn_id;
#	t: time;
#	req: socks_request_type &optional;
#	dstaddr: addr &optional;
#	dstname: string &optional;
#	p: port &optional;
#	user: string &optional;
#	service: string &optional;
#	variant: string &default = "SOCKS v4";
#	granted: string &default = "no-reply";
#};
#
#
#global conns: table[conn_id] of socks_conn;
#global proxies: set[addr] &read_expire = 24hrs;
#
#event socks_request(c: connection, t: socks_request_type, dstaddr: addr, dstname: string, p: port, user: string)
#	{
#	local id = c$id;
#
#	local sc: socks_conn;
#	sc$id = id;
#	sc$t = c$start_time;
#	sc$req = t;
#	
#	if ( dstaddr != 0.0.0.0 )
#		sc$dstaddr = dstaddr;
#	
#	if ( dstname != "" )
#		sc$dstname = dstname;
#	
#	if ( p != 0/tcp )
#		sc$p = p;
#	
#	if ( user != "" )
#		sc$user = user;
#	
#	conns[id] = sc;
#	}
#
#event socks_reply(c: connection, granted: bool, dst: addr, p: port)
#	{
#	local id = c$id;
#	local sc: socks_conn;
#	
#	if ( id in conns )
#		sc = conns[id];
#	else
#		{
#		sc$id = id;
#		sc$t = c$start_time;
#		conns[id] = sc;
#		}
#
#	sc$granted = granted ? "ok" : "denied";
#	
#	local proxy = c$id$resp_h;
#	
#	if ( proxy !in proxies )
#		{
#		NOTICE([$note=SOCKSProxy, $src=proxy, $sub=sc$variant,
#				   $msg=fmt("SOCKS proxy seen at %s (%s)", proxy, sc$variant)]);
#		add proxies[proxy];
#		}
#	}
#
#function print_conn(sc: socks_conn)
#	{
#	local req = "<unknown-type>";
#	if ( sc?$req )
#		{
#		if ( sc$req == SOCKS_CONNECTION )
#			req = "relay-to";
#		if ( sc$req == SOCKS_PORT )
#			req = "bind-port";
#		}
#	
#	local p = sc?$p ? fmt("%s", sc$p) : "<no-port>";
#	
#	local dest = sc?$dstaddr 
#		? (fmt("%s:%s%s", sc$dstaddr, p, (sc?$dstname ? fmt(" (%s)", sc$dstname) : "")))
#		: (sc?$dstname ? fmt("%s:%s", sc$dstname, p) : "<no-dest>");
#	local user = sc?$user ? fmt(" (user %s)", sc?$user) : "";
#	
#	local service = sc?$service ? fmt(" [%s]", sc$service) : "";
#	
#	print output, fmt("%.6f %s %s %s %s-> %s%s", sc$t, id_string(sc$id), req, 
#			dest, user, sc$granted, service);
#	}
#
#event connection_state_remove(c: connection)
#	{
#	if ( c$id in conns )
#		print_conn(conns[c$id]);
#	}
#
