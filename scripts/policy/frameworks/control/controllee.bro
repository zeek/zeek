##! The controllee portion of the control framework.  Load this script if remote
##! runtime control of the Bro process is desired.
##!
##! A controllee only needs to load the controllee script in addition
##! to the specific analysis scripts desired.  It may also need a node
##! configured as a controller node in the communications nodes configuration::
##!
##!     bro <scripts> frameworks/control/controllee

@load base/frameworks/control
# If an instance is a controllee, it implicitly needs to listen for remote
# connections.
@load frameworks/broker/listen

module Control;

event Control::id_value_request(id: string)
	{
	local val = lookup_ID(id);
	event Control::id_value_response(id, fmt("%s", val));
	}

event Control::peer_status_request()
	{
	local status = "";
	for ( p in Broker::nodes )
		{
		local peer = Broker::nodes[p];
		if ( ! peer$connected )
			next;

		status += fmt("%.6f peer=%s host=%s\n",
			      network_time(), peer$peer, peer$ip);
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
	
event Control::shutdown_request()
	{
	# Send the acknowledgement event.
	event Control::shutdown_response();
	# Schedule the shutdown to let the current event queue flush itself first.
	event terminate_event();
	}

event bro_init() &priority=5
	{
	# Subscribe: All nodes need to subscribe to control-related events
	local prefix = fmt("%srequest/", Control::pub_sub_prefix);
	Broker::subscribe_to_events(prefix);
	Broker::publish_topic(prefix);

	# Publish: Register responses to control events with broker
	prefix = fmt("%sresponse/", Control::pub_sub_prefix);
	Broker::publish_topic(prefix);
	for ( e in Control::controllee_events )
		Broker::auto_event(prefix, lookup_ID(e));
	}
