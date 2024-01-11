##! This script logs and tracks active services.  For this script, an active
##! service is defined as an IP address and port of a server for which
##! a TCP handshake (SYN+ACK) is observed, assumed to have been done in the
##! past (started seeing packets mid-connection, but the server is actively
##! sending data), or sent at least one UDP packet.
##! If a protocol name is found/known for service, that will be logged,
##! but services whose names can't be determined are also still logged.

@load base/utils/directions-and-hosts
@load base/frameworks/cluster

module Known;

export {
	## The known-services logging stream identifier.
	redef enum Log::ID += { SERVICES_LOG };

	## A default logging policy hook for the stream.
	global log_policy_services: Log::PolicyHook;

	## The record type which contains the column fields of the known-services
	## log.
	type ServicesInfo: record {
		## The time at which the service was detected.
		ts:             time            &log;
		## The host address on which the service is running.
		host:           addr            &log;
		## The port number on which the service is running.
		port_num:       port            &log;
		## The transport-layer protocol which the service uses.
		port_proto:     transport_proto &log;
		## A set of protocols that match the service's connection payloads.
		service:        set[string]     &log;
	};

	## Toggles between different implementations of this script.
	## When true, use a Broker data store, else use a regular Zeek set
	## with keys uniformly distributed over proxy nodes in cluster
	## operation.
	const use_service_store = F &redef;

	## Require UDP server to respond before considering it an "active service".
	option service_udp_requires_response = T;

	## The hosts whose services should be tracked and logged.
	## See :zeek:type:`Host` for possible choices.
	option service_tracking = LOCAL_HOSTS;

	type AddrPortServTriplet: record {
		host: addr;
		p: port;
		serv: string;
	};

	## Holds the set of all known services.  Keys in the store are
	## :zeek:type:`Known::AddrPortServTriplet` and their associated value is
	## always the boolean value of "true".
	global service_store: Cluster::StoreInfo;

	## The Broker topic name to use for :zeek:see:`Known::service_store`.
	const service_store_name = "zeek/known/services" &redef;

	## The expiry interval of new entries in :zeek:see:`Known::service_store`.
	## This also changes the interval at which services get logged.
	const service_store_expiry = 1day &redef;

	## The timeout interval to use for operations against
	## :zeek:see:`Known::service_store`.
	option service_store_timeout = 15sec;

	## Tracks the set of daily-detected services for preventing the logging
	## of duplicates, but can also be inspected by other scripts for
	## different purposes.
	##
	## In cluster operation, this table is uniformly distributed across
	## proxy nodes.
	##
	## This table is automatically populated and shouldn't be directly modified.
	global services: table[addr, port] of set[string] &create_expire=1day;

	## Event that can be handled to access the :zeek:type:`Known::ServicesInfo`
	## record as it is sent on to the logging framework.
	global log_known_services: event(rec: ServicesInfo);
}

redef record connection += {
	# This field is to indicate whether or not the processing for detecting
	# and logging the service for this connection is complete.
	known_services_done: bool &default=F;
};

# Check if the triplet (host,port_num,service) is already in Known::services
function check(info: ServicesInfo) : bool
	{
	if ( [info$host, info$port_num] !in Known::services )
		return F;

	for ( s in info$service )
		{
		if ( s !in Known::services[info$host, info$port_num] )
			return F;
		}

	return T;
	}

event zeek_init()
	{
	if ( ! Known::use_service_store )
		return;

	Known::service_store = Cluster::create_store(Known::service_store_name);
	}

event service_info_commit(info: ServicesInfo)
	{
	if ( ! Known::use_service_store )
		return;

	local tempservs = info$service;

	for ( s in tempservs )
		{
		local key = AddrPortServTriplet($host = info$host, $p = info$port_num, $serv = s);

		when [info, s, key] ( local r = Broker::put_unique(Known::service_store$store, key,
		                                    T, Known::service_store_expiry) )
			{
			if ( r$status == Broker::SUCCESS )
				{
				if ( r$result as bool ) {
					info$service = set(s);	# log one service at the time if multiservice
					Log::write(Known::SERVICES_LOG, info);
					}
				}
			else
				Reporter::error(fmt("%s: data store put_unique failure",
				                    Known::service_store_name));
			}
		timeout Known::service_store_timeout
			{
			Log::write(Known::SERVICES_LOG, info);
			}
		}
	}

event known_service_add(info: ServicesInfo)
	{
	if ( Known::use_service_store )
		return;

	if ( check(info) )
		return;

	if ( [info$host, info$port_num] !in Known::services )
		Known::services[info$host, info$port_num] = set();

	 # service to log can be a subset of info$service if some were already seen
	local info_to_log: ServicesInfo;
	info_to_log$ts = info$ts;
	info_to_log$host = info$host;
	info_to_log$port_num = info$port_num;
	info_to_log$port_proto = info$port_proto;
	info_to_log$service = set();

	for ( s in info$service )
		{
		if ( s !in Known::services[info$host, info$port_num] )
			{
			add Known::services[info$host, info$port_num][s];
			add info_to_log$service[s];
			}
		}

	@if ( ! Cluster::is_enabled() ||
	      Cluster::local_node_type() == Cluster::PROXY )
		Log::write(Known::SERVICES_LOG, info_to_log);
	@endif
	}

event Cluster::node_up(name: string, id: string)
	{
	if ( Known::use_service_store )
		return;

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	clear_table(Known::services);
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( Known::use_service_store )
		return;

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	clear_table(Known::services);
	}

event service_info_commit(info: ServicesInfo)
	{
	if ( Known::use_service_store )
		return;

	if ( check(info) )
		return;

	local key = cat(info$host, info$port_num);
	Cluster::publish_hrw(Cluster::proxy_pool, key, known_service_add, info);
	event known_service_add(info);
	}

function has_active_service(c: connection): bool
	{
	local proto = get_port_transport_proto(c$id$resp_p);

	switch ( proto ) {
	case tcp:
		# Not a service unless the TCP server did a handshake (SYN+ACK).
		if ( c$resp$state == TCP_ESTABLISHED ||
			 c$resp$state == TCP_CLOSED ||
			 c$resp$state == TCP_PARTIAL ||
		     /h/ in c$history )
			return T;
		return F;
	case udp:
		# Not a service unless UDP server has sent something (or the option
		# to not care about that is set).
		if ( Known::service_udp_requires_response )
			return c$resp$state == UDP_ACTIVE;
		return T;
	case icmp:
		# ICMP is not considered a service.
		return F;
	default:
		# Unknown/other transport not considered a service for now.
		return F;
	}
	}

function known_services_done(c: connection)
	{
	local id = c$id;

	if ( ! addr_matches_host(id$resp_h, service_tracking) )
		return;

	if ( |c$service| == 1 )
		{
		if ( "ftp-data" in c$service )
			# Don't include ftp data sessions.
			return;

		if ( "DNS" in c$service && c$resp$size == 0 )
			# For dns, require that the server talks.
			return;
		}

	if ( ! has_active_service(c) )
		# If we're here during a analyzer_confirmation, it's still premature
		# to declare there's an actual service, so wait for the connection
		# removal to check again (to get more timely reporting we'd have
		# schedule some recurring event to poll for handshake/activity).
		return;

	c$known_services_done = T;

	# Drop services starting with "-" (confirmed-but-then-violated protocol)
	local tempservs: set[string];
		for (s in c$service)
			if ( s[0] != "-" )
				add tempservs[s];

	local info = ServicesInfo($ts = network_time(), $host = id$resp_h,
	                          $port_num = id$resp_p,
	                          $port_proto = get_port_transport_proto(id$resp_p),
	                          $service = tempservs);

	# If no protocol was detected, wait a short time before attempting to log
	# in case a protocol is detected on another connection.
	if ( |c$service| == 0 )
		{
		# Add an empty service so the service loops will work later
		add info$service[""];
		schedule 5min { service_info_commit(info) };
		}
	else
		event service_info_commit(info);
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) &priority=-5
	{
	if ( info?$c )
		known_services_done(info$c);
	}

# Handle the connection ending in case no protocol was ever detected.
event connection_state_remove(c: connection) &priority=-5
	{
	if ( c$known_services_done )
		return;

	known_services_done(c);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(Known::SERVICES_LOG, [$columns=ServicesInfo,
	                                         $ev=log_known_services,
	                                         $path="known_services",
						 $policy=log_policy_services]);
	}
