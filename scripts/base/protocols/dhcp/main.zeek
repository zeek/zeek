##! Analyze DHCP traffic and provide a log that is organized around
##! the idea of a DHCP "conversation" defined by messages exchanged within
##! a relatively short period of time using the same transaction ID.
##! The log will have information from clients and servers to give a more
##! complete picture of what happened.

@load base/frameworks/cluster
@load ./consts

module DHCP;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	## The record type which contains the column fields of the DHCP log.
	type Info: record {
		## The earliest time at which a DHCP message over the
		## associated connection is observed.
		ts:             time        &log;

		## A series of unique identifiers of the connections over which
		## DHCP is occurring.  This behavior with multiple connections is
		## unique to DHCP because of the way it uses broadcast packets
		## on local networks.
		uids:           set[string] &log;

		## IP address of the client.  If a transaction
		## is only a client sending INFORM messages then
		## there is no lease information exchanged so this
		## is helpful to know who sent the messages.
		## Getting an address in this field does require
		## that the client sources at least one DHCP message
		## using a non-broadcast address.
		client_addr:    addr        &log &optional;
		## IP address of the server involved in actually
		## handing out the lease.  There could be other
		## servers replying with OFFER messages which won't
		## be represented here.  Getting an address in this
		## field also requires that the server handing out
		## the lease also sources packets from a non-broadcast
		## IP address.
		server_addr:    addr        &log &optional;

		## Client port number seen at time of server handing out IP (expected
		## as 68/udp).
		client_port:    port             &optional;
		## Server port number seen at time of server handing out IP (expected
		## as 67/udp).
		server_port:    port             &optional;

		## Client's hardware address.
		mac:            string      &log &optional;

		## Name given by client in Hostname option 12.
		host_name:      string      &log &optional;
		## FQDN given by client in Client FQDN option 81.
		client_fqdn:    string      &log &optional;
		## Domain given by the server in option 15.
		domain:         string      &log &optional;

		## IP address requested by the client.
		requested_addr: addr        &log &optional;
		## IP address assigned by the server.
		assigned_addr:  addr        &log &optional;
		## IP address lease interval.
		lease_time:     interval    &log &optional;

		## Message typically accompanied with a DHCP_DECLINE
		## so the client can tell the server why it rejected
		## an address.
		client_message: string      &log &optional;
		## Message typically accompanied with a DHCP_NAK to let
		## the client know why it rejected the request.
		server_message: string      &log &optional;

		## The DHCP message types seen by this DHCP transaction
		msg_types:      vector of string &log &default=string_vec();

		## Duration of the DHCP "session" representing the
		## time from the first message to the last.
		duration:       interval    &log &default=0secs;

		## The CHADDR field sent by the client.
		client_chaddr:  string      &optional;
	};

	## The maximum amount of time that a transaction ID will be watched
	## for to try and tie messages together into a single DHCP
	## transaction narrative.
	option DHCP::max_txid_watch_time = 30secs;

	## The maximum number of uids allowed in a single log entry.
	option DHCP::max_uids_per_log_entry = 10;

	## The maximum number of msg_types allowed in a single log entry.
	option DHCP::max_msg_types_per_log_entry = 50;

	## This event is used internally to distribute data around clusters
	## since DHCP doesn't follow the normal "connection" model used by
	## most protocols. It can also be handled to extend the DHCP log.
	## :zeek:see:`DHCP::log_info`.
	global DHCP::aggregate_msgs: event(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options);

	## This is a global variable that is only to be used in the
	## :zeek:see:`DHCP::aggregate_msgs` event. It can be used to avoid
	## looking up the info record for a transaction ID in every event handler
	## for :zeek:see:`DHCP::aggregate_msgs`.
	global DHCP::log_info: Info;

	## Event that can be handled to access the DHCP
	## record as it is sent on to the logging framework.
	global log_dhcp: event(rec: Info);
}

# Add the dhcp info to the connection record.
redef record connection += {
	dhcp: Info &optional;
};

redef record Info += {
	last_message_ts: time &optional;
};

# 67/udp is the server's port, 68/udp the client.
# 4011/udp seems to be some proxyDHCP thing.
const ports = { 67/udp, 68/udp, 4011/udp };
redef likely_server_ports += { 67/udp };

event zeek_init() &priority=5
	{
	Log::create_stream(DHCP::LOG, [$columns=Info, $ev=log_dhcp, $path="dhcp", $policy=log_policy]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_DHCP, ports);
	}

@if ( Cluster::is_enabled() )
event zeek_init()
	{
	Broker::auto_publish(Cluster::manager_topic, DHCP::aggregate_msgs);
	}
@endif

function join_data_expiration(t: table[count] of Info, idx: count): interval
	{
	local info = t[idx];

	local now = network_time();
	# If a message hasn't been seen in the past 5 seconds or the
	# total time watching has been more than the maximum time
	# allowed by the configuration then log this data and expire it.
	# Also, if Zeek is shutting down.
	if ( (now - info$last_message_ts) > 5sec ||
	     (now - info$ts) > max_txid_watch_time ||
	     zeek_is_terminating() )
		{
		# If client didn't send client-identifier option and we didn't see
		# a response from a server to use its chaddr field, then fill in mac
		# from the client's chaddr field.
		if ( ! info?$mac && info?$client_chaddr )
			info$mac = info$client_chaddr;

		Log::write(LOG, info);

		# Go ahead and expire the data now that the log
		# entry has been written.
		return 0secs;
		}
	else
		{
		return 5secs;
		}
	}

# This is where the data is stored as it's centralized. All data for a log must
# arrive within the expiration interval if it's to be logged fully. On a cluster,
# this data is only maintained on the manager.
global join_data: table[count] of Info = table()
	&create_expire=10secs &expire_func=join_data_expiration;



@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
# We are handling this event at priority 1000 because we really want
# the DHCP::log_info global to be set correctly before a user might try
# to access it.
event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=1000
	{
	if ( msg$xid !in join_data )
		{
		join_data[msg$xid] = Info($ts=ts,
		                          $uids=set(uid));
		}

	log_info = join_data[msg$xid];
	}

event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=5
	{
	log_info$duration = ts - log_info$ts;

	if ( uid !in log_info$uids )
		add log_info$uids[uid];

	log_info$msg_types += DHCP::message_types[msg$m_type];

	# Let's watch for messages in any DHCP message type
	# and split them out based on client and server.
	if ( options?$message )
		{
		if ( is_orig )
			log_info$client_message = options$message;
		else
			log_info$server_message = options$message;
		}

	# Update the last message time so that we can do some data
	# expiration handling.
	log_info$last_message_ts = ts;

	if ( is_orig ) # client requests
		{
		# Assign the client addr in case this is a session
		# of only INFORM messages (no lease handed out).
		# This also works if a normal lease handout uses
		# unicast.
		if ( id$orig_h != 0.0.0.0 && id$orig_h != 255.255.255.255 )
			log_info$client_addr = id$orig_h;

		if ( options?$host_name )
			log_info$host_name = options$host_name;

		if ( options?$client_fqdn )
			log_info$client_fqdn = options$client_fqdn$domain_name;

		if ( options?$client_id &&
		     options$client_id$hwtype == 1 ) # ETHERNET
			log_info$mac = options$client_id$hwaddr;
		else
			log_info$client_chaddr = msg$chaddr;

		if ( options?$addr_request )
			log_info$requested_addr = options$addr_request;
		}
	else # server reply messages
		{
		# Only log the address of the server if it handed out
		# an IP address.
		if ( msg$yiaddr != 0.0.0.0 &&
		     id$resp_h != 255.255.255.255 )
			{
			log_info$server_addr = id$resp_h;
			log_info$server_port = id$resp_p;
			log_info$client_port = id$orig_p;
			}

		# Only use the client hardware address from the server
		# if we didn't already pick one up from the client.
		if ( msg$chaddr != "" && !log_info?$mac )
			log_info$mac = msg$chaddr;

		if ( msg$yiaddr != 0.0.0.0 )
			log_info$assigned_addr = msg$yiaddr;

		# If no client address has been seen yet, let's use the assigned addr.
		if ( ! log_info?$client_addr && log_info?$assigned_addr )
			log_info$client_addr = log_info$assigned_addr;

		if ( options?$domain_name )
			log_info$domain = options$domain_name;

		if ( options?$lease )
			log_info$lease_time = options$lease;
		}

	# Write log entry if |uids| or |msg_types| becomes too large
	if ( |log_info$uids| >= max_uids_per_log_entry || |log_info$msg_types| >= max_msg_types_per_log_entry )
		{
		Log::write(LOG, log_info);
		delete join_data[msg$xid];
		}
	}
@endif



# Aggregate DHCP messages to the manager.
event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=-5
	{
	event DHCP::aggregate_msgs(network_time(), c$id, c$uid, is_orig, msg, options);
	}

event zeek_done() &priority=-5
	{
	# Log any remaining data that hasn't already been logged!
	for ( i in DHCP::join_data )
		join_data_expiration(DHCP::join_data, i);
	}
