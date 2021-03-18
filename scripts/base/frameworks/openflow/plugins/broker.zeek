##! OpenFlow plugin for interfacing to controllers via Broker.

@load base/frameworks/openflow
@load base/frameworks/broker

module OpenFlow;

export {
	redef enum Plugin += {
		BROKER,
	};

	## Broker controller constructor.
	##
	## host: Controller ip.
	##
	## host_port: Controller listen port.
	##
	## topic: Broker topic to send messages to.
	##
	## dpid: OpenFlow switch datapath id.
	##
	## Returns: OpenFlow::Controller record.
	global broker_new: function(name: string, host: addr, host_port: port, topic: string, dpid: count): OpenFlow::Controller;

	redef record ControllerState += {
		## Controller ip.
		broker_host: addr &optional;
		## Controller listen port.
		broker_port: port &optional;
		## OpenFlow switch datapath id.
		broker_dpid: count &optional;
		## Topic to send events for this controller to.
		broker_topic: string &optional;
	};

	global broker_flow_mod: event(name: string, dpid: count, match: ofp_match, flow_mod: ofp_flow_mod);
	global broker_flow_clear: event(name: string, dpid: count);
}

global broker_peers: table[port, string] of Controller;

function broker_describe(state: ControllerState): string
	{
	return fmt("Broker-%s:%d-%d", state$broker_host, state$broker_port, state$broker_dpid);
	}

function broker_flow_mod_fun(state: ControllerState, match: ofp_match, flow_mod: OpenFlow::ofp_flow_mod): bool
	{
	Broker::publish(state$broker_topic, Broker::make_event(broker_flow_mod, state$_name, state$broker_dpid, match, flow_mod));

	return T;
	}

function broker_flow_clear_fun(state: OpenFlow::ControllerState): bool
	{
	Broker::publish(state$broker_topic, Broker::make_event(broker_flow_clear, state$_name, state$broker_dpid));

	return T;
	}

function broker_init(state: OpenFlow::ControllerState)
	{
	Broker::subscribe(state$broker_topic); # openflow success and failure events are directly sent back via the other plugin via broker.
	Broker::peer(cat(state$broker_host), state$broker_port);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	local peer_address = cat(endpoint$network$address);
	local peer_port = endpoint$network$bound_port;
	if ( [peer_port, peer_address] !in broker_peers )
		# ok, this one was none of ours...
		return;

	local p = broker_peers[peer_port, peer_address];
	controller_init_done(p);
	delete broker_peers[peer_port, peer_address];
	}

# broker controller constructor
function broker_new(name: string, host: addr, host_port: port, topic: string, dpid: count): OpenFlow::Controller
	{
	local c = OpenFlow::Controller($state=OpenFlow::ControllerState($broker_host=host, $broker_port=host_port, $broker_dpid=dpid, $broker_topic=topic),
		$flow_mod=broker_flow_mod_fun, $flow_clear=broker_flow_clear_fun, $describe=broker_describe, $supports_flow_removed=T, $init=broker_init);

	register_controller(OpenFlow::BROKER, name, c);

	if ( [host_port, cat(host)] in broker_peers )
		Reporter::warning(fmt("Peer %s:%s was added to NetControl openflow plugin twice.", host, host_port));
	else
		broker_peers[host_port, cat(host)] = c;

	return c;
	}
