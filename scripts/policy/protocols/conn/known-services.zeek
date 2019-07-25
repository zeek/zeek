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

	## Toggles between different implementations of this script.
	## When true, use a Broker data store, else use a regular Zeek set
	## with keys uniformly distributed over proxy nodes in cluster
	## operation.
	const use_service_store = T &redef;
	
	## The hosts whose services should be tracked and logged.
	## See :zeek:type:`Host` for possible choices.
	option service_tracking = LOCAL_HOSTS;

	type AddrPortServTriplet: record {
		host: addr;
		p: port;
		serv: set[string];
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

	if ( |info$service| == 0 )
		return T;  # don't log empty service

        for(s in info$service)
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

	local key = AddrPortServTriplet($host = info$host, $p = info$port_num, $serv = info$service);

	when ( local r = Broker::put_unique(Known::service_store$store, key,
	                                    T, Known::service_store_expiry) )
		{
		if ( r$status == Broker::SUCCESS )
			{
			if ( r$result as bool )
				Log::write(Known::SERVICES_LOG, info);
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

event known_service_add(info: ServicesInfo)
	{
	if ( Known::use_service_store )
		return;

        if ( check(info) )
                return;

	if([info$host, info$port_num] !in Known::services)
		Known::services[info$host, info$port_num] = set();

	for(s in info$service)
		{
		if ( s !in Known::services[info$host, info$port_num] )
			{
			add Known::services[info$host, info$port_num][s];
			}
		}

	@if ( ! Cluster::is_enabled() ||
	      Cluster::local_node_type() == Cluster::PROXY )
		Log::write(Known::SERVICES_LOG, info);
	@endif
	}

event Cluster::node_up(name: string, id: string)
	{
	if ( Known::use_service_store )
		return;

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	Known::services = table();
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( Known::use_service_store )
		return;

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	Known::services = table();
	}

event service_info_commit(info: ServicesInfo)
	{
	if ( Known::use_service_store )
		return;

	if ( check(info) )
		return;

	local key = cat(info$host, info$port_num, info$service);
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

	# TODO: this is a temporary patch, because sometimes in c$service the protocol name is written with "-" 
	# at the beginning. This comes from the analyzers (I've seen it for HTTP and SSL), but causes problems
	# when checking for known_services on triplets (host, port, services). The service starting with "-" (i.e. -HTTP) is 
	# reconized as different from the normal one (HTTP).
	# It would be better to correct the analyzers some time later...
	local tempservs : set[string];
        for (s in c$service)
        	if ( s[0] == "-" )
			add tempservs[s[1:]];
		else
			add tempservs[s];
              		
	local info = ServicesInfo($ts = network_time(), $host = id$resp_h,
	                          $port_num = id$resp_p,
	                          $port_proto = get_port_transport_proto(id$resp_p),
	                          $service = tempservs);

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

event zeek_init() &priority=5
	{
	Log::create_stream(Known::SERVICES_LOG, [$columns=ServicesInfo,
	                                         $ev=log_known_services,
	                                         $path="known_services"]);
	}

