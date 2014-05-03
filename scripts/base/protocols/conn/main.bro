##! This script manages the tracking/logging of general information regarding
##! TCP, UDP, and ICMP traffic.  For UDP and ICMP, "connections" are to
##! be interpreted using flow semantics (sequence of packets from a source
##! host/port to a destination host/port).  Further, ICMP "ports" are to
##! be interpreted as the source port meaning the ICMP message type and
##! the destination port being the ICMP message code.

@load base/utils/site

module Conn;

export {
	## The connection logging stream identifier.
	redef enum Log::ID += { LOG };

	## The record type which contains column fields of the connection log.
	type Info: record {
		## This is the time of the first packet.
		ts:           time            &log;
		## A unique identifier of the connection.
		uid:          string          &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:           conn_id         &log;
		## The transport layer protocol of the connection.
		proto:        transport_proto &log;
		## An identification of an application protocol being sent over
		## the connection.
		service:      string          &log &optional;
		## How long the connection lasted.  For 3-way or 4-way connection
		## tear-downs, this will not include the final ACK.
		duration:     interval        &log &optional;
		## The number of payload bytes the originator sent. For TCP
		## this is taken from sequence numbers and might be inaccurate
		## (e.g., due to large connections).
		orig_bytes:   count           &log &optional;
		## The number of payload bytes the responder sent. See
		## *orig_bytes*.
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

		## If the connection is originated locally, this value will be T.
		## If it was originated remotely it will be F.  In the case that
		## the :bro:id:`Site::local_nets` variable is undefined, this
		## field will be left empty at all times.
		local_orig:   bool            &log &optional;

		## Indicates the number of bytes missed in content gaps, which
		## is representative of packet loss.  A value other than zero
		## will normally cause protocol analysis to fail but some
		## analysis may have been completed prior to the packet loss.
		missed_bytes: count           &log &default=0;

		## Records the state history of connections as a string of
		## letters.  The meaning of those letters is:
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
		## If the event comes from the originator, the letter is in
		## upper-case; if it comes from the responder, it's in
		## lower-case. Multiple packets of the same type will only be
		## noted once (e.g. we only record one "d" in each direction,
		## regardless of how many data packets were seen.)
		history:      string          &log &optional;
		## Number of packets that the originator sent.
		## Only set if :bro:id:`use_conn_size_analyzer` = T.
		orig_pkts:     count      &log &optional;
		## Number of IP level bytes that the originator sent (as seen on
		## the wire, taken from the IP total_length header field).
		## Only set if :bro:id:`use_conn_size_analyzer` = T.
		orig_ip_bytes: count      &log &optional;
		## Number of packets that the responder sent.
		## Only set if :bro:id:`use_conn_size_analyzer` = T.
		resp_pkts:     count      &log &optional;
		## Number of IP level bytes that the responder sent (as seen on
		## the wire, taken from the IP total_length header field).
		## Only set if :bro:id:`use_conn_size_analyzer` = T.
		resp_ip_bytes: count      &log &optional;
		## If this connection was over a tunnel, indicate the
		## *uid* values for any encapsulating parent connections
		## used over the lifetime of this inner connection.
		tunnel_parents: set[string] &log;
	};

	## Event that can be handled to access the :bro:type:`Conn::Info`
	## record as it is sent on to the logging framework.
	global log_conn: event(rec: Info);
}

redef record connection += {
	conn: Info &optional;
};

event bro_init() &priority=5
	{
	Log::create_stream(Conn::LOG, [$columns=Info, $ev=log_conn]);
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
	if ( c?$tunnel && |c$tunnel| > 0 )
		add c$conn$tunnel_parents[c$tunnel[|c$tunnel|-1]$uid];
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

event tunnel_changed(c: connection, e: EncapsulatingConnVector) &priority=5
	{
	set_conn(c, F);
	if ( |e| > 0 )
		add c$conn$tunnel_parents[e[|e|-1]$uid];
	c$tunnel = e;
	}

event connection_state_remove(c: connection) &priority=5
	{
	set_conn(c, T);
	}

event connection_state_remove(c: connection) &priority=-5
	{
	Log::write(Conn::LOG, c$conn);
	}

