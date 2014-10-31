@load ../main
@load ../utils/json
@load base/utils/exec
@load base/utils/active-http


module Openflow;


export {
	## The Ryu openflow controller IP.
	const controller_ip = "0.0.0.0" &redef;
	## The port where the ReST API listens on.
	const controller_port = "8080" &redef;

	## Ryu error definitions.
	type RyuError: enum {
		## The controller IP needs to be redefined.
		CONTROLLER_IP_REDEF,
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
	global Openflow::ryu_error: event(flow_mod: ofp_flow_mod, error: RyuError, msg: string &default="");
}


# Openflow no buffer constant.
const OFP_NO_BUFFER = 0xffffffff;


# Ryu ReST API flow_mod URL-path
const RYU_FLOWENTRY_PATH = "/stats/flowentry/";


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
type ryu_flow_mod: record {
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


# Hook to register the Ryu openflow plugin's flow_mod function
# as the one the openflow framework should use.
hook register_openflow_plugin()
	{
	register_openflow_mod_func(
		function(dpid: count, flow_mod: ofp_flow_mod): bool
			{
			# Check if the controller_ip has been redefined.
			if(controller_ip == "0.0.0.0")
				{
				Reporter::warning(fmt("The constant Openflow::controller_ip must be redefined"));
				event Openflow::ryu_error(flow_mod, CONTROLLER_IP_REDEF, cat(controller_ip));
				return F;
				}
			# Generate ryu_flow_actions because their type differs (using strings as type).
			local _flow_actions: vector of ryu_flow_action_output;
			for(i in flow_mod$actions)
				{
				switch(flow_mod$actions[i]$_type)
					{
					case OFPAT_OUTPUT:
						_flow_actions[|_flow_actions|] = ryu_flow_action_output($_port=flow_mod$actions[i]$_port);
						break;
					default:
						Reporter::warning(fmt("The given Openflow action type '%s' is not available", flow_mod$actions[i]$_type));
						event Openflow::ryu_error(flow_mod, ACTION_TYPE_NOT_AVAILABLE, cat(flow_mod$actions[i]$_type));
						return F;
					}
				}
			# Generate our ryu_flow_mod record for the ReST API call.
			local _flow_mod: ryu_flow_mod = ryu_flow_mod(
				$dpid=dpid,
				$cookie=generate_cookie(flow_mod$cookie),
				$idle_timeout=flow_mod$idle_timeout,
				$hard_timeout=flow_mod$hard_timeout,
				$match=flow_mod$match,
				$actions=_flow_actions
			);
			# Type of the command
			local command_type: string;
			switch(flow_mod$command)
				{
				case OFPFC_ADD:
					command_type = "add";
					break;
				case OFPFC_DELETE:
					command_type = "delete";
					break;
				default:
					Reporter::warning(fmt("The given Openflow command type '%s' is not available", result$body));
					event Openflow::ryu_error(flow_mod, COMMAND_TYPE_NOT_AVAILABLE, cat(flow_mod$command));
					return F;
				}
			# Create the ActiveHTTP request and convert the record to a Ryu ReST API JSON string
			local request: ActiveHTTP::Request = ActiveHTTP::Request(
				$url=cat("http://", controller_ip, ":", controller_port, RYU_FLOWENTRY_PATH, command_type),
				$method="POST",
				$client_data=JSON::convert(_flow_mod)
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
	);
	}
