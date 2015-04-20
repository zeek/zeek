@load base/frameworks/openflow

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
	## dpid: OpenFlow switch datapath id.
	##
	## Returns: OpenFlow::Controller record
	global broker_new: function(host: addr, host_port: port, dpid: count): OpenFlow::Controller;

	redef record ControllerState += {
		## Controller ip.
		broker_host: addr &optional;
		## Controller listen port.
		broker_port: port &optional;
		## OpenFlow switch datapath id.
		broker_dpid: count &optional;
	};

	global broker_flow_mod: event(dpid: count, match: ofp_match, flow_mod: ofp_flow_mod);
	global broker_flow_clear: event(dpid: count);
}

function broker_describe(state: ControllerState): string
	{
	return fmt("Broker Plugin - %s:%d - DPID: %d", state$broker_host, state$broker_port, state$broker_dpid);
	}

function broker_flow_mod_fun(state: ControllerState, match: ofp_match, flow_mod: OpenFlow::ofp_flow_mod): bool
	{
	event OpenFlow::broker_flow_mod(state$broker_dpid, match, flow_mod);

	return T;
	}

function broker_flow_clear_fun(state: OpenFlow::ControllerState): bool
	{
	event OpenFlow::broker_flow_clear(state$broker_dpid);

	return T;
	}

# broker controller constructor
function broker_new(host: addr, host_port: port, dpid: count): OpenFlow::Controller
	{
	BrokerComm::enable();
	BrokerComm::auto_event("bro/event/openflow", broker_flow_mod);
	BrokerComm::auto_event("bro/event/openflow", broker_flow_clear);
	BrokerComm::connect(cat(host), host_port, 1sec);

	return [$state=[$broker_host=host, $broker_port=host_port, $broker_dpid=dpid, $_plugin=OpenFlow::BROKER],
		$flow_mod=broker_flow_mod_fun, $flow_clear=broker_flow_clear_fun, $describe=broker_describe];
	}

