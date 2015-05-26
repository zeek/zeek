@load base/frameworks/openflow
@load base/utils/active-http
@load base/utils/exec
@load base/utils/json

module OpenFlow;

export {
	redef enum Plugin += {
		RYU,
	};

	## Ryu controller constructor.
	##
	## host: Controller ip.
	##
	## host_port: Controller listen port.
	##
	## dpid: OpenFlow switch datapath id.
	##
	## Returns: OpenFlow::Controller record
	global ryu_new: function(host: addr, host_port: count, dpid: count): OpenFlow::Controller;

	redef record ControllerState += {
		## Controller ip.
		ryu_host: addr &optional;
		## Controller listen port.
		ryu_port: count &optional;
		## OpenFlow switch datapath id.
		ryu_dpid: count &optional;
		## Enable debug mode - output JSON to stdout; do not perform actions
		ryu_debug: bool &default=F;
	};
}

# Ryu ReST API flow_mod URL-path
const RYU_FLOWENTRY_PATH = "/stats/flowentry/";
# Ryu ReST API flow_stats URL-path
#const RYU_FLOWSTATS_PATH = "/stats/flow/";

# Ryu ReST API action_output type.
type ryu_flow_action: record {
	# Ryu uses strings as its ReST API output action.
	_type: string;
	# The output port for type OUTPUT
	_port: count &optional;
};

# The ReST API documentation can be found at
# https://media.readthedocs.org/pdf/ryu/latest/ryu.pdf
# Ryu ReST API flow_mod type.
type ryu_ofp_flow_mod: record {
	dpid: count;
	cookie: count &optional;
	cookie_mask: count &optional;
	table_id: count &optional;
	idle_timeout: count &optional;
	hard_timeout: count &optional;
	priority: count &optional;
	flags: count &optional;
	match: OpenFlow::ofp_match;
	actions: vector of ryu_flow_action;
	out_port: count &optional;
	out_group: count &optional;
};

# Mapping between ofp flow mod commands and ryu urls
const ryu_url: table[ofp_flow_mod_command] of string = {
	[OFPFC_ADD] = "add",
	[OFPFC_MODIFY] = "modify",
	[OFPFC_MODIFY_STRICT] = "modify_strict",
	[OFPFC_DELETE] = "delete",
	[OFPFC_DELETE_STRICT] = "delete_strict",
};

# Ryu flow_mod function
function ryu_flow_mod(state: OpenFlow::ControllerState, match: ofp_match, flow_mod: OpenFlow::ofp_flow_mod): bool
	{
	if ( state$_plugin != RYU )
		{
		Reporter::error("Ryu openflow plugin was called with state of non-ryu plugin");
		return F;
		}

	# Generate ryu_flow_actions because their type differs (using strings as type).
	local flow_actions: vector of ryu_flow_action = vector();

	for ( i in flow_mod$actions$out_ports )
		flow_actions[|flow_actions|] = ryu_flow_action($_type="OUTPUT", $_port=flow_mod$actions$out_ports[i]);

	# Generate our ryu_flow_mod record for the ReST API call.
	local mod: ryu_ofp_flow_mod = ryu_ofp_flow_mod(
		$dpid=state$ryu_dpid,
		$cookie=OpenFlow::generate_cookie(flow_mod$cookie),
		$idle_timeout=flow_mod$idle_timeout,
		$hard_timeout=flow_mod$hard_timeout,
		$priority=flow_mod$priority,
		$flags=flow_mod$flags,
		$match=match,
		$actions=flow_actions
	);

	if ( flow_mod?$out_port )
		mod$out_port = flow_mod$out_port;
	if ( flow_mod?$out_group )
		mod$out_group = flow_mod$out_group;

	# Type of the command
	local command_type: string;

	if ( flow_mod$command in ryu_url )
		command_type = ryu_url[flow_mod$command];
	else
			{
			Reporter::warning(fmt("The given OpenFlow command type '%s' is not available", cat(flow_mod$command)));
			return F;
			}

	local url=cat("http://", cat(state$ryu_host), ":", cat(state$ryu_port), RYU_FLOWENTRY_PATH, command_type);

	if ( state$ryu_debug )
		{
		print url;
		print to_json(mod);
		event OpenFlow::flow_mod_success(match, flow_mod);
		return T;
		}

	# Create the ActiveHTTP request and convert the record to a Ryu ReST API JSON string
	local request: ActiveHTTP::Request = ActiveHTTP::Request(
		$url=url,
		$method="POST",
		$client_data=to_json(mod)
	);

	# Execute call to Ryu's ReST API
	when ( local result = ActiveHTTP::request(request) )
		{
		if(result$code == 200)
			event OpenFlow::flow_mod_success(match, flow_mod, result$body);
		else
			{
			Reporter::warning(fmt("Flow modification failed with error: %s", result$body));
			event OpenFlow::flow_mod_failure(match, flow_mod, result$body);
			return F;
			}
		}

	return T;
	}

function ryu_flow_clear(state: OpenFlow::ControllerState): bool
	{
	local url=cat("http://", cat(state$ryu_host), ":", cat(state$ryu_port), RYU_FLOWENTRY_PATH, "clear", "/", state$ryu_dpid);

	if ( state$ryu_debug )
		{
		print url;
		return T;
		}

	local request: ActiveHTTP::Request = ActiveHTTP::Request(
		$url=url,
		$method="DELETE"
	);

	when ( local result = ActiveHTTP::request(request) )
		{
		}

	return T;
	}

function ryu_describe(state: ControllerState): string
	{
	return fmt("Ryu Plugin - http://%s:%d - DPID: %d", state$ryu_host, state$ryu_port, state$ryu_dpid);
	}

# Ryu controller constructor
function ryu_new(host: addr, host_port: count, dpid: count): OpenFlow::Controller
	{
	local c = OpenFlow::Controller($state=OpenFlow::ControllerState($ryu_host=host, $ryu_port=host_port, $ryu_dpid=dpid),
		$flow_mod=ryu_flow_mod, $flow_clear=ryu_flow_clear, $describe=ryu_describe, $supports_flow_removed=F);

	register_controller(OpenFlow::RYU, cat(host,host_port,dpid), c);

	return c;
	}
