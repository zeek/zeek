##! The controllee portion of the control framework.  Load this script if remote
##! runtime control of the Zeek process is desired.
##!
##! A controllee only needs to load the controllee script in addition
##! to the specific analysis scripts desired.  It may also need a node
##! configured as a controller node in the communications nodes configuration::
##!
##!     zeek <scripts> frameworks/control/controllee

@load base/frameworks/control
@load base/frameworks/broker

module Control;

function make_controller_topic(node_id: string, resp_event_name: string): string
	{ return fmt("%s/%s/%s", Control::topic_prefix, node_id, resp_event_name); }

event zeek_init() &priority=-10
	{
	Broker::subscribe(Control::topic_prefix + "/" + Broker::node_id());

	if ( Control::controllee_listen )
		Broker::listen();
	}

event Control::id_value_request(id: string, node_id: string)
	{
	local val = lookup_ID(id);
	event Control::id_value_response(id, fmt("%s", val));
	Broker::publish(make_controller_topic(node_id, "id_value_response"),
	                Control::id_value_response, id, fmt("%s", val));
	}

event Control::peer_status_request(node_id: string)
	{
	local status = "";

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

	event Control::peer_status_response(status);
	Broker::publish(make_controller_topic(node_id, "peer_status_response"),
	                Control::peer_status_response, status);
	}

event Control::net_stats_request(node_id: string)
	{
	local ns = get_net_stats();
	local reply = fmt("%.6f recvd=%d dropped=%d link=%d\n", network_time(),
	                  ns$pkts_recvd, ns$pkts_dropped, ns$pkts_link);
	event Control::net_stats_response(reply);
	Broker::publish(make_controller_topic(node_id, "net_stats_response"),
	                Control::net_stats_response, reply);
	}

event Control::configuration_update_request(node_id: string)
	{
	# Generate the alias event.
	event Control::configuration_update();

	# Don't need to do anything in particular here, it's just indicating that
	# the configuration is going to be updated.  This event could be handled
	# by other scripts if they need to do some ancilliary processing if
	# redef-able consts are modified at runtime.
	event Control::configuration_update_response();
	Broker::publish(make_controller_topic(node_id, "configuration_update_response"),
	                Control::configuration_update_response);
	}

event Control::shutdown_request(node_id: string)
	{
	# Send the acknowledgement event.
	event Control::shutdown_response();
	Broker::publish(make_controller_topic(node_id, "shutdown_response"),
	                Control::shutdown_response);
	# Schedule the shutdown to let the current event queue flush itself first.
	schedule 1sec { terminate_event() };
	}
