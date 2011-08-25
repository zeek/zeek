
module Conn;

export {
	redef enum Log::ID += { CONN };

	type Info: record {
		## This is the time of the first packet.
		ts:           time            &log;
		uid:          string          &log;
		id:           conn_id         &log;
		proto:        transport_proto &log;
		service:      string          &log &optional;
		duration:     interval        &log &optional;
		## The number of payload bytes the originator sent. For TCP
		## this is taken from sequence numbers and might be inaccurate 
		## (e.g., due to large connections)
		orig_bytes:   count           &log &optional;
		## The number of payload bytes the responder sent. See ``orig_bytes``.
		resp_bytes:   count           &log &optional;

		## ==========   ===============================================
		## conn_state   Meaning
		## ==========   ===============================================
		## S0           Connection attempt seen, no reply.
		## S1           Connection established, not terminated.
		## SF           Normal establishment and termination. Note that this is the same symbol as for state S1. You can tell the two apart because for S1 there will not be any byte counts in the summary, while for SF there will be.
		## REJ          Connection attempt rejected.
		## S2           Connection established and close attempt by originator seen (but no reply from responder).
		## S3           Connection established and close attempt by responder seen (but no reply from originator).
		## RSTO         Connection established, originator aborted (sent a RST).
		## RSTR         Established, responder aborted.
		## RSTOS0       Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder.
		## RSTRH        Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator.
		## SH           Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was "half" open).
		## SHR          Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator.
		## OTH          No SYN seen, just midstream traffic (a "partial connection" that was not later closed).
		## ==========   ===============================================
		conn_state:   string          &log &optional;
		
		## If the connection is originated locally, this value will be T.  If
		## it was originated remotely it will be F.  In the case that the
		## :bro:id:`Site::local_nets` variable is undefined, this field will 
		## be left empty at all times.
		local_orig:   bool            &log &optional;
		
		## Indicates the number of bytes missed in content gaps which is
		## representative of packet loss.  A value other than zero will 
		## normally cause protocol analysis to fail but some analysis may 
		## have been completed prior to the packet loss.
		missed_bytes: count           &log &default=0;

		## Records the state history of (TCP) connections as
		## a string of letters.
		##
		## ======  ====================================================
		## Letter  Meaning
		## ======  ====================================================
		## s       a SYN w/o the ACK bit set
		## h       a SYN+ACK ("handshake")
		## a       a pure ACK
		## d       packet with payload ("data")
		## f       packet with FIN bit set
		## r       packet with RST bit set
		## c       packet with a bad checksum
		## i       inconsistent packet (e.g. SYN+RST bits both set)
		## ======  ====================================================
		##
		## If the letter is in upper case it means the event comes from the
		## originator and lower case then means the responder.
		## Also, there is compression. We only record one "d" in each direction,
		## for instance. I.e., we just record that data went in that direction.
		## This history is not meant to encode how much data that happened to be.
		history:      string          &log &optional;
		## Number of packets the originator sent.
		## Only set if :bro:id:`use_conn_size_analyzer`=T
		orig_pkts:     count      &log &optional;
		## Number IP level bytes the originator sent (as seen on the wire,
		## taken from IP total_length header field).
		## Only set if :bro:id:`use_conn_size_analyzer`=T
		orig_ip_bytes: count      &log &optional;
		## Number of packets the responder sent. See ``orig_pkts``.
		resp_pkts:     count      &log &optional;
		## Number IP level bytes the responder sent. See ``orig_pkts``.
		resp_ip_bytes: count      &log &optional;
	};
	
	global log_conn: event(rec: Info);
}

redef record connection += {
	conn: Info &optional;
};

event bro_init() &priority=5
	{
	Log::create_stream(CONN, [$columns=Info, $ev=log_conn]);
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

## Fill out the c$conn record for logging
function set_conn(c: connection, eoc: bool)
	{
	if ( ! c?$conn )
		{
		local tmp: Info;
		c$conn = tmp;
		}

	c$conn$ts=c$start_time;
	c$conn$uid=c$uid;
	c$conn$id=c$id;
	c$conn$proto=get_port_transport_proto(c$id$resp_p);
	if( |Site::local_nets| > 0 )
		c$conn$local_orig=Site::is_local_addr(c$id$orig_h);
	
	if ( eoc )
		{
		if ( c$duration > 0secs ) 
			{
			c$conn$duration=c$duration;
			c$conn$orig_bytes=c$orig$size;
			c$conn$resp_bytes=c$resp$size;
			}
		if ( c$orig?$num_pkts )
			{
			# these are set if use_conn_size_analyzer=T
			# we can have counts in here even without duration>0
			c$conn$orig_pkts = c$orig$num_pkts;
			c$conn$orig_ip_bytes = c$orig$num_bytes_ip;
			c$conn$resp_pkts = c$resp$num_pkts;
			c$conn$resp_ip_bytes = c$resp$num_bytes_ip;
			}
		local service = determine_service(c);
		if ( service != "" ) 
			c$conn$service=service;
		c$conn$conn_state=conn_state(c, get_port_transport_proto(c$id$resp_p));

		if ( c$history != "" )
			c$conn$history=c$history;
		}
	}

event content_gap(c: connection, is_orig: bool, seq: count, length: count) &priority=5
	{
	set_conn(c, F);
	
	c$conn$missed_bytes = c$conn$missed_bytes + length;
	}
	
event connection_state_remove(c: connection) &priority=5
	{
	set_conn(c, T);
	}

event connection_state_remove(c: connection) &priority=-5
	{
	Log::write(CONN, c$conn);
	}

