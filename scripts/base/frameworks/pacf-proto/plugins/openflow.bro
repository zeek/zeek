@load ../main
@load base/frameworks/openflow


module PACFOpenflow;


export {
	redef enum PACF::Plugin += {
		PACF::OPENFLOW,
	};

	redef record PACF::BackendState += {
		openflow_controller: Openflow::Controller &optional;
	};

	global new: function(controller: Openflow::Controller): PACF::Backend;
}


function insert(state: PACF::BackendState, rule: PACF::Rule): bool
	{
	for(i in rule$action)
		{
		switch(rule$action[i]$type_)
			{
			case PACF::DROP:
				if(!state?$openflow_controller)
					{
					Reporter::warning(fmt("The given PACF::Backend %s is not an PACFOpenflow backend", cat(state)));
					return F;
					}
				
				# Create openflow records
				local nw_proto = Openflow::IP_TCP;
				if(rule$match$ip_proto == udp)
					nw_proto = Openflow::IP_UDP;
				else if(rule$match$ip_proto == icmp)
					nw_proto = Openflow::IP_ICMP;

				local match: Openflow::ofp_match = [
					$in_port=state$openflow_controller$state$port_state[rule$match$src_ip],
					$nw_src=rule$match$src_ip,
					$nw_dst=rule$match$dst_ip,
					$nw_proto=nw_proto,
					$tp_src=rule$match$src_port,
					$tp_dst=rule$match$dst_port
				];

				local flow_mod: Openflow::ofp_flow_mod = [
					$match=match,
					#$cookie=cookie,
					$idle_timeout=30,
					$hard_timeout=0,
					# No action means drop.
					$actions=vector()
				];

				if(rule$direction == PACF::BIDIRECTIONAL)
					{
					local reverse_match: Openflow::ofp_match = [
						$in_port=state$openflow_controller$state$port_state[rule$match$dst_ip],
						$nw_src=rule$match$dst_ip,
						$nw_dst=rule$match$src_ip,
						$nw_proto=nw_proto,
						$tp_src=rule$match$dst_port,
						$tp_dst=rule$match$src_port
					];
					
					local reverse_flow_mod: Openflow::ofp_flow_mod = [
						$match=reverse_match,
						#$cookie=cookie,
						$idle_timeout=30,
						$hard_timeout=0,
						# No action means drop.
						$actions=vector()
					];
					}

				if(rule$action[i]$target == PACF::MONITOR)
					{
					local action: vector of Openflow::ofp_action_output;
					action[|action|] = Openflow::ofp_action_output($port_=state$openflow_controller$state$port_state[rule$match$dst_ip]);
					flow_mod$actions=action;

					if(rule$direction == PACF::BIDIRECTIONAL)
						{
						local reverse_action: vector of Openflow::ofp_action_output;
						reverse_action[|reverse_action|] = Openflow::ofp_action_output($port_=state$openflow_controller$state$port_state[rule$match$src_ip]);
						reverse_flow_mod$actions=reverse_action;
						}
					}
		
				if(rule$direction == PACF::BIDIRECTIONAL)
					return Openflow::flow_mod(state$openflow_controller, flow_mod) && Openflow::flow_mod(state$openflow_controller, reverse_flow_mod);
				else
					return Openflow::flow_mod(state$openflow_controller, flow_mod);
				break;
			default:
				Reporter::warning(fmt("The PACF ActionType %s is not supported by this plugin", cat(rule$action[i]$type_)));
				break;
			}
		}
	return F;
	}


function new(controller: Openflow::Controller): PACF::Backend
	{
	return [$type_=PACF::OPENFLOW, $state=[$openflow_controller=controller], $insert=insert];
	}
