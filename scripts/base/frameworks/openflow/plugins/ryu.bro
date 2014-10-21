@load ../main
@load ../utils/json
@load base/utils/exec
@load base/utils/active-http

module Openflow;

export {
	const controller_uri = "http://10.255.0.20:8080/stats/flowentry/add" &redef;
}

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
type ryu_flow_add: record {
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
		function(
			dpid: count, cookie: count, idle_timeout: count, hard_timeout: count,
			actions: vector of ofp_action_output, match: ofp_match): bool {
			local ryu_flow_actions: vector of ryu_flow_action_output;
			for(i in actions) {
				if(actions[i]$_type == Openflow::OFPAT_OUTPUT) {
					ryu_flow_actions[|ryu_flow_actions|] = ryu_flow_action_output($_port=actions[i]$_port);
				}
			}
			# Generate our record for the restAPI.
			local ryu_flow_mod: ryu_flow_add = ryu_flow_add($dpid=dpid, $cookie=cookie, $idle_timeout=idle_timeout, $hard_timeout=hard_timeout, $match=match, $actions=ryu_flow_actions);
			# Create the ActiveHTTP request and convert the record to a JSON string
			local request: ActiveHTTP::Request = ActiveHTTP::Request($url=controller_uri, $method="POST", $client_data=JSON::convert(ryu_flow_mod));
			# Execute call to RyuRestAPI
			when(local result = ActiveHTTP::request(request)) {
				if(result$code == 200) {
					print fmt("Flow %s:%s -> %s:%s removed from monitor", match$nw_src, match$tp_src, match$nw_dst, match$tp_dst);
				} else {
					print fmt("Error: could no add shunt flow, restAPI returned:\n%s", result);
					return F;
				}				
			}

			# Add reverse flow because openflow only uses unidirectional flows.
			if(|actions| == 1 && (match$dl_type == ETH_IPv4 || match$dl_type == ETH_IPv6)) {
				local reverse_match: ofp_match;
				local reverse_actions: vector of ryu_flow_action_output;
				reverse_actions[|reverse_actions|] = ryu_flow_action_output($_port=match$in_port);
				reverse_match = ofp_match($in_port=actions[0]$_port, $dl_type=match$dl_type, $nw_proto=match$nw_proto, $nw_src=match$nw_dst, $nw_dst=match$nw_src, $tp_src=match$tp_dst, $tp_dst=match$tp_src);
				local reverse_flow_mod: ryu_flow_add = ryu_flow_add($dpid=dpid, $cookie=cookie, $idle_timeout=idle_timeout, $hard_timeout=hard_timeout, $match=reverse_match, $actions=reverse_actions);
				local reverse_request: ActiveHTTP::Request = ActiveHTTP::Request($url=controller_uri, $method="POST", $addl_curl_args=fmt("-d '%s'", JSON::convert(reverse_flow_mod)));
				when(local result2 = ActiveHTTP::request(reverse_request)) {
					if(result2$code == 200) {
						print fmt("Flow %s:%s -> %s:%s removed from monitor", reverse_match$nw_src, reverse_match$tp_src, reverse_match$nw_dst, reverse_match$tp_dst);
					} else {
						print fmt("Error: could no add shunt flow, restAPI returned:\n%s", result2);
						return F;
					}
				}
			}
			return T;
		}
	);
}
