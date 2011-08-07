##! Handle tunneled connections.  
##! 
##! Bro can decapsulate IPinIP and IPinUDP tunnels, were "IP" can be either
##! IPv4 or IPv6. The most common case will be decapsulating Teredo, 6to4,
##! 6in4, and AYIAY. When this script is loaded, decapsulation will be 
##! enabled. "tunnel.log" will log the "parent" for each tunneled 
##! connection. The identity (and existence) of the tunnel connection
##! is otherwise lost. 
##!
##! Currently handles: 
##!
##!   * IP6 in IP{4,6}. (IP4 in IP is easy to add, but omitted due to lack
##!     of test cases.
##!   * IP{4,6} in UDP. This decapsulates e.g., standard *Teredo* packets
##!     (without authentication or origin indicator)
##!   * IP{4,6} in AYIAY
##!   * Only checks for UDP tunnels on Teredo's and AYIAY's default 
##!     ports. See :bro:id:`udp_tunnel_ports` and 
##!     :bro:id:`udp_tunnel_allports`
##! 
##! Decapsulation happens early in a packets processing, right after IP
##! defragmentation but before there is a connection context. The tunnel
##! headers are stripped from packet and the identity of the parent is 
##! is stored as the ``tunnel_parent`` member of :bro:type:`connection`, 
##! which is of type :bro:type:`parent_t`. 
##! 
##! *Limitation:* The decapsulated packets are not fed through the 
##! defragmenter again and decapsulation happens only on the primary
##! path, i.e., it's not available for the secondary path. 
##! 
##! 

module Tunnel; 

#redef use_connection_compressor = F;
redef Tunnel::decapsulate_ip = T;
redef Tunnel::decapsulate_udp = T;
redef Tunnel::udp_tunnel_allports = T;

export {
	redef enum Log::ID += { TUNNEL };

	## This record will be logged 
	type Info : record {
		## This is the time of the first record
		ts:       time            &log;
		## The uid of the child connection, i.e. the connection in the tunnel
		uid:      string          &log;
		## The connection id of the child
		id:       conn_id         &log;
		## The child's transport protocol
		proto:    transport_proto &log;
		## The parent connection of IP-pair
		parent:   parent_t        &log;
	};
	global log_conn: event(rec: Info);
}

event bro_init()
	{
	Log::create_stream(TUNNEL, [$columns=Info, $ev=log_conn]);
	}

event new_connection(c: connection)
	{
	if (c?$tunnel_parent)
		{
		local info: Info;
		info$ts = c$start_time;
		info$uid = c$uid;
		info$id = c$id;
		info$proto = get_port_transport_proto(c$id$resp_p);
		info$parent = c$tunnel_parent;
		Log::write(TUNNEL, info);
		}
	}
