@load ../main
@load ../utils/json
@load base/utils/exec
@load base/utils/active-http


module OpenflowRyu;


export {
	redef enum Openflow::Plugin += {
		Openflow::RYU,
	};

	## Ryu error definitions.
	type Error: enum {
		## The openflow command type is not available
		## for this ryu openflow plugin.
		COMMAND_TYPE_NOT_AVAILABLE,
		## The openflow action type is not available
		## for this ryu openflow plugin.
		ACTION_TYPE_NOT_AVAILABLE,
	};

	## Ryu error event.
	##
	## flow_mod: The openflow flow_mod record which describes
	##           the flow to delete, modify or add.
	##
	## error: The error why the plugin aborted.
	##
	## msg: More detailed error description.
	global OpenflowRyu::error: event(flow_mod: Openflow::ofp_flow_mod, error: Error, msg: string &default="");

	## Ryu controller constructor.
	##
	## ip: Controller ip.
	##
	## port_: Controller listen port.
	##
	## dpid: Openflow switch datapath id.
	##
	## Returns: Openflow::Controller record
	global new: function(ip: addr, port_: count, dpid: count): Openflow::Controller;
}


# Openflow no buffer constant.
const OFP_NO_BUFFER = 0xffffffff;


# Ryu ReST API flow_mod URL-path
const RYU_FLOWENTRY_PATH = "/stats/flowentry/";
# Ryu ReST API flow_stats URL-path
const RYU_FLOWSTATS_PATH = "/stats/flow/";


# Ryu ReST API action_output type.
type ryu_flow_action_output: record {
	# Ryu uses strings as its ReST API output action.
	# The type should be never changed...
	# but constants are not possible in a record.
	_type: string &default="OUTPUT";
	# The output port
	_port: count;
};


# The ReST API documentation can be found at
# https://media.readthedocs.org/pdf/ryu/latest/ryu.pdf
# on page 278-299 (30.10.2014)
# Ryu ReST API flow_mod type.
type ryu_ofp_flow_mod: record {
	dpid: count;
	cookie: count &optional;
	cookie_mask: count &optional;
	table_id: count &optional;
	idle_timeout: count &optional;
	hard_timeout: count &optional;
	priority: count &optional;
	buffer_id: count &optional;
	flags: count &optional;
	match: Openflow::ofp_match;
	actions: vector of ryu_flow_action_output;
};


# Ryu flow_mod function
function flow_mod(state: Openflow::ControllerState, flow_mod: Openflow::ofp_flow_mod): bool
	{
	# Generate ryu_flow_actions because their type differs (using strings as type).
	local _flow_actions: vector of ryu_flow_action_output;
	for(i in flow_mod$actions)
		{
		switch(flow_mod$actions[i]$type_)
			{
			case Openflow::OFPAT_OUTPUT:
				_flow_actions[|_flow_actions|] = ryu_flow_action_output($_port=flow_mod$actions[i]$port_);
				break;
			default:
				Reporter::warning(fmt("The given Openflow action type '%s' is not available", flow_mod$actions[i]$type_));
				event OpenflowRyu::error(flow_mod, ACTION_TYPE_NOT_AVAILABLE, cat(flow_mod$actions[i]$type_));
				return F;
			}
		}
	# Generate our ryu_flow_mod record for the ReST API call.
	local _flow_mod: ryu_ofp_flow_mod = ryu_ofp_flow_mod(
		$dpid=state$dpid,
		$cookie=Openflow::generate_cookie(flow_mod$cookie),
		$idle_timeout=flow_mod$idle_timeout,
		$hard_timeout=flow_mod$hard_timeout,
		$match=flow_mod$match,
		$actions=_flow_actions
	);
	# Type of the command
	local command_type: string;
	switch(flow_mod$command)
		{
		case Openflow::OFPFC_ADD:
			command_type = "add";
			break;
		case Openflow::OFPFC_DELETE:
			command_type = "delete";
			break;
		default:
			Reporter::warning(fmt("The given Openflow command type '%s' is not available", cat(flow_mod$command)));
			event OpenflowRyu::error(flow_mod, COMMAND_TYPE_NOT_AVAILABLE, cat(flow_mod$command));
			return F;
		}
	# Create the ActiveHTTP request and convert the record to a Ryu ReST API JSON string
	local request: ActiveHTTP::Request = ActiveHTTP::Request(
		$url=cat("http://", cat(state$ip), ":", cat(state$port_), RYU_FLOWENTRY_PATH, command_type),
		$method="POST",
		$client_data=OpenflowJSON::convert(_flow_mod)
	);
	# Execute call to Ryu's ReST API
	when(local result = ActiveHTTP::request(request))
		{
		if(result$code == 200)
			event Openflow::flow_mod_success(flow_mod, result$body);
		else
			{
			Reporter::warning(fmt("Flow modification failed with error: %s", result$body));
			event Openflow::flow_mod_failure(flow_mod, result$body);
			return F;
			}
		}

	return T;
	}


# Ryu controller constructor
function new(ip: addr, port_: count, dpid: count): Openflow::Controller
	{
	return [$state=[$ip=ip, $port_=port_, $type_=Openflow::RYU, $dpid=dpid], $flow_mod=flow_mod];
	}