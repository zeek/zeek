##! The controllee portion of the control framework.  Load this script if remote
##! runtime control of the Bro process is desired.
##!
##! A controllee only needs to load the controllee script in addition
##! to the specific analysis scripts desired.  It may also need a node
##! configured as a controller node in the communications nodes configuration::
##!
##!     bro <scripts> frameworks/control/controllee

@load base/frameworks/control
@load base/frameworks/communication
@load base/frameworks/broker

module Control;

event bro_init() &priority=-10
	{
	if ( use_broker )
		{
		Broker::subscribe("bro/event/framework/control");
		Broker::auto_publish("bro/event/framework/control/id_value_response",
		                     Control::id_value_response);
		Broker::auto_publish("bro/event/framework/control/peer_status_response",
		                     Control::peer_status_response);
		Broker::auto_publish("bro/event/framework/control/net_stats_response",
		                     Control::net_stats_response);
		Broker::auto_publish("bro/event/framework/control/configuration_update_response",
		                     Control::configuration_update_response);
		Broker::auto_publish("bro/event/framework/control/shutdown_response",
		                     Control::shutdown_response);
		Broker::listen();
		}
	else
		{
		enable_communication();
		listen(Communication::listen_interface,
			   Communication::listen_port, Communication::listen_ssl,
			   Communication::listen_ipv6, Communication::listen_ipv6_zone_id,
			   Communication::listen_retry);
		}
	}

event Control::id_value_request(id: string)
	{
	local val = lookup_ID(id);
	event Control::id_value_response(id, fmt("%s", val));
	}

event Control::peer_status_request()
	{
	local status = "";

	if ( use_broker )
		{
		# @todo: need to expose broker::endpoint::peers and broker::peer_status
		local peers = Broker::peers();

		for ( i in peers )
			{
			local bpeer = peers[i];
			status += fmt("%.6f peer=%s host=%s status=%s\n",
			              network_time(),
			              bpeer$peer$id,
			              bpeer$peer$network$address,
			              bpeer$status);
			}
		}
	else
		{
		for ( p in Communication::nodes )
			{
			local peer = Communication::nodes[p];
			if ( ! peer$connected )
				next;

			status += fmt("%.6f peer=%s host=%s\n",
					  network_time(), peer$peer$descr, peer$host);
			}
		}

	event Control::peer_status_response(status);
	}

event Control::net_stats_request()
	{
	local ns = get_net_stats();
	local reply = fmt("%.6f recvd=%d dropped=%d link=%d\n", network_time(),
	                  ns$pkts_recvd, ns$pkts_dropped, ns$pkts_link);
	event Control::net_stats_response(reply);
	}

event Control::configuration_update_request()
	{
	# Generate the alias event.
	event Control::configuration_update();

	# Don't need to do anything in particular here, it's just indicating that
	# the configuration is going to be updated.  This event could be handled
	# by other scripts if they need to do some ancilliary processing if
	# redef-able consts are modified at runtime.
	event Control::configuration_update_response();
	}

event Control::shutdown_request()
	{
	# Send the acknowledgement event.
	event Control::shutdown_response();
	# Schedule the shutdown to let the current event queue flush itself first.
	event terminate_event();
	}

event Control::global_id_update_request(serialized_globals: string)
	{
	local ids = unserialize(serialized_globals) as id_table;

	for ( id in ids )
		{
		local sid = ids[id];

		if ( sid?$value )
			{
			# If the ID was not initialized on the other side.  We could
			# probably try to unset its value (if it has one) here, but I don't
			# see any reason why someone would want that behavior.

			if ( ! update_ID(id, sid$value) )
				Reporter::warning(fmt("control framework failed to update ID %s", id));
			}
		}
	}
