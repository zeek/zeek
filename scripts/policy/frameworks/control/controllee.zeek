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

event zeek_init() &priority=-10
	{
	if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER )
		{
		Broker::subscribe(Control::topic_prefix + "/" + Broker::node_id());

		if ( Control::controllee_listen )
			Broker::listen();
		}
	}

event Control::id_value_request(id: string)
	{
	local val = lookup_ID(id);
	local reply_topic = Control::topic_prefix + "/id_value_response/" + Cluster::node;
	Cluster::publish(reply_topic, Control::id_value_response, id, fmt("%s", val));
	}

event Control::peer_status_request()
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

	local topic = Control::topic_prefix + "/peer_status_response/" + Cluster::node;
	Cluster::publish(topic, Control::peer_status_response, status);
	}

event Control::net_stats_request()
	{
	local ns = get_net_stats();
	local reply = fmt("%.6f recvd=%d dropped=%d link=%d\n", network_time(),
	                  ns$pkts_recvd, ns$pkts_dropped, ns$pkts_link);
	local topic = Control::topic_prefix + "/net_stats_response/" + Cluster::node;
	Cluster::publish(topic, Control::net_stats_response, reply);
	}

event Control::configuration_update_request()
	{
	# Generate the alias event.
	event Control::configuration_update();

	# Don't need to do anything in particular here, it's just indicating that
	# the configuration is going to be updated.  This event could be handled
	# by other scripts if they need to do some ancillary processing if
	# redef-able consts are modified at runtime.
	local topic = Control::topic_prefix + "/configuration_update_response/" + Cluster::node;
	Cluster::publish(topic, Control::configuration_update_response);
	}

event Control::shutdown_request()
	{
	# Send the acknowledgement event.
	local topic = Control::topic_prefix + "/shutdown_response/" + Cluster::node;
	Cluster::publish(topic, Control::shutdown_response);
	# Schedule the shutdown to let the current event queue flush itself first.
	schedule 1sec { terminate_event() };
	}
