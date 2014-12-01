@load base/protocols/conn
@load base/frameworks/notice
@load base/frameworks/pacf/main
@load base/frameworks/openflow


module PACFOpenflowShunt;


# pox
# global param_dpid = "00-24-a8-5c-0c-00|15" &redef;
# global param_port = "\"OFPP_ALL\"" &redef;
# global of_ctrl_uri = "http://10.255.0.20:8080/OF/" &redef;
# const cmd = "curl -i -X POST -d '{\"method\":\"set_table\",\"params\":{\"dpid\":\"%s\",\"flows\":[{\"actions\":[{\"type\":\"OFPAT_OUTPUT\",\"port\":%s}],\"match\":{%s}}]}}' %s";


# default constants which are not automatically gathered.
const dpid = 4222282094087168;
const cookie = 0;
const idle_timeout = 30;
const hard_timeout = 0;
const in_port = 3;
const out_port = 1;
global delete_flow: bool = F;


export {
	## Number of bytes transferred before shunting a flow.
	const size_threshold = 1024000 &redef;

	## Base amount of time between checking
	const poll_interval = 1sec &redef;

	## Raised when a shunt happened.
	##
	## c: The connection pertaining to the data channel.
	global shunt_triggered: event(c: connection);
}


function size_callback(c: connection, cnt: count): interval
	{
	local controller = OpenflowRyu::new(10.255.0.20, 8080, dpid);
	controller$state$port_state[10.15.0.30/32] = 3;
	controller$state$port_state[10.15.0.31/32] = 1;
	local pacf_backend = PACFOpenflow::new(controller);
	# print Openflow::flow_stats(dpid);
	# if traffic exceeds the given threshold, remove flow.
	if ( c$orig$num_bytes_ip + c$resp$num_bytes_ip >= size_threshold )
		{
		# create openflow flow_mod add records from connection data and give default constants
		local action: vector of PACF::RuleAction;
		action[|action|] = [
			$type_=DROP,
			$target=MONITOR
		];

		local ip_proto = tcp;
		if(is_udp_port(c$id$orig_p))
			ip_proto = udp;
		else if(is_icmp_port(c$id$orig_p))
			ip_proto = icmp;

		local match: PACF::RuleMatch = [
			$src_ip=c$id$resp_h,
			$dst_ip=c$id$orig_h,
			$ip_proto=ip_proto,
			$src_port=c$id$resp_p,
			$dst_port=c$id$orig_p
		];

		local rule: PACF::Rule = [
			$match=match,
			$action=action,
			$direction=PACF::BIDIRECITONAL
		];

		if(pacf_backend$insert(pacf_backend, rule)
			event shunt_triggered(c);
	
		return -1sec;
		}
	return poll_interval;
	}


event connection_established(c: connection)
	{
	print fmt("new connection");
	ConnPolling::watch(c, size_callback, 0, 0secs);
	}


event Openflow::flow_mod_success(flow_mod: Openflow::ofp_flow_mod, msg: string)
	{
	print fmt("succsess, %s", cat(flow_mod));
	}


event Openflow::flow_mod_failure(flow_mod: Openflow::ofp_flow_mod, msg: string)
	{
	print fmt("failed, %s", cat(flow_mod));
	}


event OpenflowRyu::error(flow_mod: Openflow::ofp_flow_mod, error: OpenflowRyu::Error, msg: string)
	{
	print fmt("ERROR: %s, msg: %s\n%s", error, msg, flow_mod);
	}
