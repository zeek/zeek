@load ../main
@load ../utils/json
@load base/utils/exec
@load base/utils/active-http

module Openflow;

export {
	const controller_ip = "10.255.0.20" &redef;
	const controller_port = "8080" &redef;
}

const OFP_NO_BUFFER = 0xffffffff;
const RYU_FLOWENTRY_PATH = "/stats/flowentry/";

type ryu_flow_action_output: record {
	# The type should be never changed...
	# but constants are not possible in a record.
	_type: string &default="OUTPUT";
	# The output port
	_port: count;
};

# The restAPI documentation can be found at
# https://media.readthedocs.org/pdf/ryu/latest/ryu.pdf
# on page 278-299
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

# register the ryu openflow plugin flow_mod function
hook register_openflow_plugin() {
	register_openflow_mod_func(
		function(dpid: count, flow_mod: ofp_flow_mod): bool {
			# Generate ryu_flow_actions because their type differs (using strings as type).
			local _flow_actions: vector of ryu_flow_action_output;
			for(i in flow_mod$actions) {
				switch(flow_mod$actions[i]$_type) {
					case OFPAT_OUTPUT:
						_flow_actions[|_flow_actions|] = ryu_flow_action_output($_port=flow_mod$actions[i]$_port);
						break;
					default:
						print fmt("Error: flow action '%s' not available", flow_mod$actions[i]$_type);
						return F;
				}
			}
			# Generate our ryu_flow_mod record for the restAPI call.
			local _flow_mod: ryu_flow_mod = ryu_flow_mod(
				$dpid=dpid,
				$cookie=flow_mod$cookie,
				$idle_timeout=flow_mod$idle_timeout,
				$hard_timeout=flow_mod$hard_timeout,
				$match=flow_mod$match,
				$actions=_flow_actions
			);
			# Type of the command
			local command_type: string;
			switch(flow_mod$command) {
				case OFPFC_ADD:
					command_type = "add";
					break;
				case OFPFC_DELETE:
					command_type = "delete";
					break;
				default:
					print fmt("Error: command type '%s' not available", flow_mod$command);
					return F;
			}
			# Create the ActiveHTTP request and convert the record to a ryu restAPI JSON string
			local request: ActiveHTTP::Request = ActiveHTTP::Request(
				$url=cat("http://", controller_ip, ":", controller_port, RYU_FLOWENTRY_PATH, command_type),
				$method="POST",
				$client_data=JSON::convert(_flow_mod)
			);
			# Execute call to ryu's restAPI
			when(local result = ActiveHTTP::request(request)) {
				if(result$code == 200) {
					print fmt(
						"%sed flow %s:%s -> %s:%s",
						command_type,
						flow_mod$match$nw_src,
						flow_mod$match$tp_src,
						flow_mod$match$nw_dst,
						flow_mod$match$tp_dst
					);
				} else {
					print fmt("Error: could not %s flow, restAPI returned:\n%s", command_type, result);
					return F;
				}				
			}

			# Add reverse flow because openflow only uses unidirectional flows.
			if(|flow_mod$actions| == 1 && (flow_mod$match$dl_type == ETH_IPv4 || flow_mod$match$dl_type == ETH_IPv6)) {
				local reverse_flow_match: ofp_match;
				local reverse_flow_actions: vector of ryu_flow_action_output;
				reverse_flow_actions[|reverse_flow_actions|] = ryu_flow_action_output($_port=flow_mod$match$in_port);
				reverse_flow_match = ofp_match(
					$in_port=flow_mod$actions[0]$_port,
					$dl_type=flow_mod$match$dl_type,
					$nw_proto=flow_mod$match$nw_proto,
					$nw_src=flow_mod$match$nw_dst,
					$nw_dst=flow_mod$match$nw_src,
					$tp_src=flow_mod$match$tp_dst,
					$tp_dst=flow_mod$match$tp_src
				);
				local reverse_flow_mod: ryu_flow_mod = ryu_flow_mod(
					$dpid=dpid,
					$cookie=flow_mod$cookie,
					$idle_timeout=flow_mod$idle_timeout,
					$hard_timeout=flow_mod$hard_timeout,
					$match=reverse_flow_match,
					$actions=reverse_flow_actions
				);
				local reverse_request: ActiveHTTP::Request = ActiveHTTP::Request(
					$url=cat("http://", controller_ip, ":", controller_port, RYU_FLOWENTRY_PATH, command_type),
					$method="POST",
					$client_data=JSON::convert(reverse_flow_mod)
				);
				when(local result2 = ActiveHTTP::request(reverse_request)) {
					if(result2$code == 200) {
						print fmt(
							"%sed flow %s:%s -> %s:%s",
							command_type,
							reverse_flow_match$nw_src,
							reverse_flow_match$tp_src,
							reverse_flow_match$nw_dst,
							reverse_flow_match$tp_dst
						);
					} else {
						print fmt("Error: could not %s flow, restAPI returned:\n%s", command_type, result2);
						return F;
					}
				}
			}
			return T;
		}
	);
}
