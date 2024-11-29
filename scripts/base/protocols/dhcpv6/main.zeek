@load base/frameworks/cluster
@load ./consts

module DHCPv6;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	## The record type which contains the column fields of the DHCP log.
	type Info: record {
		## The earliest time at which a DHCP message over the
		## associated connection is observed.
		ts:             time        &log;
	};

	## Event that can be handled to access the DHCP
	## record as it is sent on to the logging framework.
	global log_dhcpv6: event(rec: Info);
}

# Add the dhcp info to the connection record.
redef record connection += {
	dhcpv6: Info &optional;
};

const ports = { 546/udp, 547/udp };
redef likely_server_ports += { 547/udp };

event zeek_init() &priority=5
	{
	Log::create_stream(DHCP::LOG, [$columns=Info, $ev=log_dhcpv6, $path="dhcpv6", $policy=log_policy]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_DHCPV6, ports);
	}


# Aggregate DHCP messages to the manager.
event dhcpv6_message(c: connection, is_orig: bool)
	{
	print c$uid, c$id, is_orig;
#	if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
#		Broker::publish(Cluster::manager_topic, DHCP::aggregate_msgs,
#		                network_time(), c$id, c$uid, is_orig, msg, options);
#	else
#		event DHCP::aggregate_msgs(network_time(), c$id, c$uid, is_orig, msg, options);
	}

event zeek_done() &priority=-5
	{
	# Log any remaining data that hasn't already been logged!
	# for ( i in DHCP::join_data )
	#	join_data_expiration(DHCP::join_data, i);
	}
