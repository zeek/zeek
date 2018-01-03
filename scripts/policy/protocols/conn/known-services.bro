##! This script logs and tracks services.  In the case of this script, a service
##! is defined as an IP address and port which has responded to and fully 
##! completed a TCP handshake with another host.  If a protocol is detected
##! during the session, the protocol will also be logged.

@load base/utils/directions-and-hosts
@load base/frameworks/cluster

module Known;

export {
	## The known-services logging stream identifier.
	redef enum Log::ID += { SERVICES_LOG };

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
	
	## The hosts whose services should be tracked and logged.
	## See :bro:type:`Host` for possible choices.
	const service_tracking = LOCAL_HOSTS &redef;

	## Tracks the set of daily-detected services for preventing the logging
	## of duplicates, but can also be inspected by other scripts for
	## different purposes.
	##
	## In cluster operation, this set is uniformly distributed across
	## proxy nodes.
	##
	## This set is automatically populated and shouldn't be directly modified.
	global services: set[addr, port] &create_expire=1day;

	## Event that can be handled to access the :bro:type:`Known::ServicesInfo`
	## record as it is sent on to the logging framework.
	global log_known_services: event(rec: ServicesInfo);
}

redef record connection += {
	# This field is to indicate whether or not the processing for detecting 
	# and logging the service for this connection is complete.
	known_services_done: bool &default=F;
};

event bro_init() &priority=5
	{
	Log::create_stream(Known::SERVICES_LOG, [$columns=ServicesInfo,
	                                         $ev=log_known_services,
	                                         $path="known_services"]);
	}

event known_service_add(info: ServicesInfo)
	{
	if ( [info$host, info$port_num] in Known::services )
		return;

	add Known::services[info$host, info$port_num];

	@if ( ! Cluster::is_enabled() ||
	      Cluster::local_node_type() == Cluster::PROXY )
		Log::write(Known::SERVICES_LOG, info);
	@endif
	}

event Cluster::node_up(name: string, id: string)
	{
	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	Known::services = set();
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	Known::services = set();
	}

event service_info_commit(info: ServicesInfo)
	{
	local key = cat(info$host, info$port_num);
	Cluster::publish_hrw(Cluster::proxy_pool, key, known_service_add, info);
	event known_service_add(info);
	}

function known_services_done(c: connection)
	{
	local id = c$id;
	c$known_services_done = T;

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

	local info = ServicesInfo($ts = network_time(), $host = id$resp_h,
	                          $port_num = id$resp_p,
	                          $port_proto = get_port_transport_proto(id$resp_p),
	                          $service = c$service);

	# If no protocol was detected, wait a short time before attempting to log
	# in case a protocol is detected on another connection.
	if ( |c$service| == 0 )
		schedule 5min { service_info_commit(info) };
	else 
		event service_info_commit(info);
	}
	
event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=-5
	{
	known_services_done(c);
	}

# Handle the connection ending in case no protocol was ever detected.
event connection_state_remove(c: connection) &priority=-5
	{
	if ( c$known_services_done )
		return;

	if ( c$resp$state != TCP_ESTABLISHED )
		return;

	known_services_done(c);
	}
