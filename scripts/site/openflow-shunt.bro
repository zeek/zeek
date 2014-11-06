@load base/protocols/conn
@load base/frameworks/notice
@load base/frameworks/openflow

module OpenflowShunt;

# pox
# global param_dpid = "00-24-a8-5c-0c-00|15" &redef;
# global param_port = "\"OFPP_ALL\"" &redef;
# global of_ctrl_uri = "http://10.255.0.20:8080/OF/" &redef;
# const cmd = "curl -i -X POST -d '{\"method\":\"set_table\",\"params\":{\"dpid\":\"%s\",\"flows\":[{\"actions\":[{\"type\":\"OFPAT_OUTPUT\",\"port\":%s}],\"match\":{%s}}]}}' %s";


# default constants which are not automatically gathered.
redef Openflow::controller_ip = "10.255.0.20";
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
	# print Openflow::flow_stats(dpid);
	# if traffic exceeds the given threshold, remove flow.
	if ( c$orig$num_bytes_ip + c$resp$num_bytes_ip >= size_threshold )
		{
		# create openflow flow_mod add records from connection data and give default constants
		local actions: vector of Openflow::ofp_action_output;
		local reverse_actions: vector of Openflow::ofp_action_output;
		actions[|actions|] = Openflow::ofp_action_output($_port=out_port);
		reverse_actions[|reverse_actions|] = Openflow::ofp_action_output($_port=in_port);
		# flow layer 4 protocol
		local nw_proto = Openflow::IP_TCP;
		if(is_udp_port(c$id$orig_p))
			nw_proto = Openflow::IP_UDP;
		else if(is_icmp_port(c$id$orig_p))
			nw_proto = Openflow::IP_ICMP;

		local match: Openflow::ofp_match = [
			$in_port=in_port,
			$nw_src=c$id$orig_h,
			$nw_dst=c$id$resp_h,
			$nw_proto=nw_proto,
			$tp_src=c$id$orig_p,
			$tp_dst=c$id$resp_p
		];

		local reverse_match: Openflow::ofp_match = [
			$in_port=out_port,
			$nw_src=c$id$resp_h,
			$nw_dst=c$id$orig_h,
			$nw_proto=nw_proto,
			$tp_src=c$id$resp_p,
			$tp_dst=c$id$orig_p
		];

		local command = Openflow::OFPFC_ADD;
		if(delete_flow)
			command = Openflow::OFPFC_DELETE;
		local flow_mod: Openflow::ofp_flow_mod = [
			$match=match,
			$cookie=cookie,
			$command=command,
			$idle_timeout=idle_timeout,
			$hard_timeout=hard_timeout,
			$actions=actions
		];
		local reverse_flow_mod: Openflow::ofp_flow_mod = [
			$match=reverse_match,
			$cookie=cookie,
			$command=command,
			$idle_timeout=idle_timeout,
			$hard_timeout=hard_timeout,
			$actions=reverse_actions
		];

		# call openflow framework
		if(Openflow::flow_mod(dpid, flow_mod) && Openflow::flow_mod(dpid, reverse_flow_mod)) {
			event shunt_triggered(c);
		}

		if(delete_flow)
			{
			delete_flow = F;
			return -1sec;
			}
		else
			{
			delete_flow = T;
			return 15sec;
			}
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


event Openflow::ryu_error(flow_mod: Openflow::ofp_flow_mod, error: Openflow::RyuError, msg: string)
	{
	print fmt("ERROR: %s, msg: %s\n%s", error, msg, flow_mod);
	}
