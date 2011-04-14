@load functions

module Conn;

export {
	redef enum Log::ID += { CONN };
	type Log: record {
		## This is the time at which the connection was "fully established";
		ts:           time            &log;
		id:           conn_id         &log;
		proto:        transport_proto &log;
		service:      string          &log &optional;
		duration:     interval        &log &optional;
		orig_bytes:   count           &log &optional;
		resp_bytes:   count           &log &optional;
		conn_state:   string          &log &optional;
		local_orig:   bool            &log &optional;
		
		# TODO: should these fields be included in the default log?
		#addl:         string   &optional;
		#history:      string   &optional;
	};
	
	# Configure if only a certain direction of connection is desired.
	# TODO: implement this as a filter
	const logging = Enabled &redef;
	
	global log_conn: event(rec: Log);
}

redef record connection += {
	log: Log &optional;
};

event bro_init()
	{
	Log::create_stream(CONN, [$columns=Log, $ev=log_conn]);
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

	return to_lower(service);
	}

function set_conn_log(c: connection, eoc: bool)
	{
	if ( ! c?$log )
		{
		local id = c$id;
		local conn_log: Log;
		conn_log$ts=c$start_time;
		conn_log$id=id;
		conn_log$proto=get_port_transport_proto(id$resp_p);
		if( |local_nets| > 0 )
			conn_log$local_orig=is_local_addr(id$orig_h);
		c$log = conn_log;
		}
	
	if ( eoc )
		{
		if ( c$duration > 0secs ) 
			{
			c$log$duration=c$duration;
			# TODO: these should optionally use Gregor's new
			#       actual byte counting code if it's enabled.
			c$log$orig_bytes=c$orig$size;
			c$log$resp_bytes=c$resp$size;
			}
		local service = determine_service(c);
		if ( service != "" ) 
			c$log$service=service;
		c$log$conn_state=conn_state(c, get_port_transport_proto(c$id$resp_p));
		
		# TODO: should these fields be included in the default logs?
		#c$log$addl=c$addl;
		#c$log$history=c$history;
		}
	}

event connection_established(c: connection) &priority = 5
	{
	set_conn_log(c, F);
	}

event connection_state_remove(c: connection) &priority = -5
	{
	set_conn_log(c, T);
	Log::write(CONN, c$log);
	}
