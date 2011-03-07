@load functions

module Conn;

export {
	redef enum Log::ID += { CONN };
	type Log: record {
		start_time:   time;
		orig_h:       addr;
		orig_p:       count;
		resp_h:       addr;
		resp_p:       count;
		proto:        transport_proto;
		service:      string   &optional;
		duration:     interval &optional;
		orig_bytes:   count    &optional;
		resp_bytes:   count    &optional;
		conn_state:   string   &default="";
		local_orig:   bool     &optional;
		addl:         string   &optional;
		history:      string   &optional;
	};
	
	# Only log connections appear successful.
	# TODO: implement this as a filter
	const only_log_successful = T &redef;

	# Configure if only a certain direction of connection is desired.
	# TODO: implement this as a filter
	const logging = Enabled &redef;

	# If inbound/outbound connections are to be split into separate files.
	# TODO: implement a log splitting option as a filter here too (inbound/outbound)
	const split_log = F &redef;

	# This is where users can get access to the active Log record for a
	# connection so they can extend and enhance the logged data.
	global active_conns: table[conn_id] of Log;
}

event bro_init()
	{
	Log::create_stream("CONN", "Conn::Log");
	Log::add_default_filter("CONN");
	}

function conn_state(c: connection, trans: transport_proto): string
	{
	local os = c$orig$state;
	local rs = c$resp$state;

	local o_inactive = os == TCP_INACTIVE || os == TCP_PARTIAL;
	local r_inactive = rs == TCP_INACTIVE || rs == TCP_PARTIAL;

	if ( trans == tcp )
		{
		if ( rs == TCP_RESET )
			{
			if ( os == TCP_SYN_SENT || os == TCP_SYN_ACK_SENT ||
			     (os == TCP_RESET &&
			      c$orig$size == 0 && c$resp$size == 0) )
				return "REJ";
			else if ( o_inactive )
				return "RSTRH";
			else
				return "RSTR";
			}
		else if ( os == TCP_RESET )
			return r_inactive ? "RSTOS0" : "RSTO";
		else if ( rs == TCP_CLOSED && os == TCP_CLOSED )
			return "SF";
		else if ( os == TCP_CLOSED )
			return r_inactive ? "SH" : "S2";
		else if ( rs == TCP_CLOSED )
			return o_inactive ? "SHR" : "S3";
		else if ( os == TCP_SYN_SENT && rs == TCP_INACTIVE )
			return "S0";
		else if ( os == TCP_ESTABLISHED && rs == TCP_ESTABLISHED )
			return "S1";
		else
			return "OTH";
		}

	else if ( trans == udp )
		{
		if ( os == UDP_ACTIVE )
			return rs == UDP_ACTIVE ? "SF" : "S0";
		else
			return rs == UDP_ACTIVE ? "SHR" : "OTH";
		}

	else
		return "OTH";
	}

function determine_service(c: connection): string
	{
	local service = "";
	for ( s in c$service )
		{
		if ( sub_bytes(s, 0, 1) != "-" )
			service = service == "" ? s : cat(service, ",", s);
		}

	return service == "" ? "other" : to_lower(service);
	}

function get_conn_log(c: connection): Log
	{
	local id = c$id;
	local conn_log: Log;
	if ( c$id in active_conns )
		conn_log = active_conns[id];
	else
		{
		conn_log$start_time=c$start_time;
		conn_log$orig_h=id$orig_h;
		conn_log$orig_p=port_to_count(id$orig_p);
		conn_log$resp_h=id$resp_h;
		conn_log$resp_p=port_to_count(id$resp_p);
		conn_log$proto=get_port_transport_proto(id$resp_p);
		conn_log$local_orig=is_local_addr(id$orig_h);
		}
		
	conn_log$duration=c$duration;
	conn_log$service=determine_service(c);
	# TODO: these should optionally use Gregor's new
	#       actual byte counting code if it's enabled.
	conn_log$orig_bytes=c$orig$size;
	conn_log$resp_bytes=c$resp$size;
	conn_log$conn_state=conn_state(c, get_port_transport_proto(c$id$resp_p));
	conn_log$addl=c$addl;
	conn_log$history=c$history;
	
	return conn_log;
	}

event connection_established(c: connection) &priority = 10
	{
	active_conns[c$id] = get_conn_log(c);
	}

event connection_state_remove(c: connection) &priority = -10
	{
	local conn_log = get_conn_log(c);
	Log::write("CONN", conn_log);
	
	if ( c$id in active_conns )
		delete active_conns[c$id];
	}
