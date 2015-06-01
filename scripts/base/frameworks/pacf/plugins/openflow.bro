@load ../plugin
@load base/frameworks/openflow

module Pacf;

export {
	type OfConfig: record {
		monitor: bool &default=T;
		forward: bool &default=T;
		idle_timeout: count &default=0;
		table_id: count &optional;
		priority_offset: int &default=+0; ##< add this to all rule priorities. Can be useful if you want the openflow priorities be offset from the pacf priorities without having to write a filter function.

		check_pred: function(p: PluginState, r: Rule): bool &optional &weaken;
		match_pred: function(p: PluginState, e: Entity, m: vector of OpenFlow::ofp_match): vector of OpenFlow::ofp_match &optional &weaken;
		flow_mod_pred: function(p: PluginState, r: Rule, m: OpenFlow::ofp_flow_mod): OpenFlow::ofp_flow_mod &optional &weaken;
	};

	redef record PluginState += {
		## OpenFlow controller for Pacf OpenFlow plugin
		of_controller: OpenFlow::Controller &optional;
		## OpenFlow configuration record that is passed on initialization
		of_config: OfConfig &optional;
	};

	type OfTable: record {
		p: PluginState;
		r: Rule;
		c: count &default=0; # how many replies did we see so far? needed for ids where we have multiple rules...
		packet_count: count &default=0;
		byte_count: count &default=0;
		duration_sec: double &default=0.0;
	};

	## the time interval after which an openflow message is considered to be timed out
	## and we delete it from our internal tracking.
	const openflow_message_timeout = 20secs &redef;

	## the time interval after we consider a flow timed out. This should be fairly high (or
	## even disabled) if you expect a lot of long flows. However, one also will have state
	## buildup for quite a while if keeping this around...
	const openflow_flow_timeout = 24hrs &redef;

	## Instantiates an openflow plugin for the PACF framework.
	global create_openflow: function(controller: OpenFlow::Controller, config: OfConfig &default=[]) : PluginState;
}

global of_messages: table[count, OpenFlow::ofp_flow_mod_command] of OfTable &create_expire=openflow_message_timeout
	&expire_func=function(t: table[count, OpenFlow::ofp_flow_mod_command] of OfTable, idx: any): interval
		{
		local rid: count;
		local command: OpenFlow::ofp_flow_mod_command;
		[rid, command] = idx;

		local p = t[rid, command]$p;
		local r = t[rid, command]$r;
		event Pacf::rule_error(r, p, "Timeout during rule insertion/removal");
		return 0secs;
		};

global of_flows: table[count] of OfTable &create_expire=openflow_flow_timeout;

function openflow_name(p: PluginState) : string
	{
	return fmt("Openflow - %s", p$of_controller$describe(p$of_controller$state));
	}

function openflow_check_rule(p: PluginState, r: Rule) : bool
	{
	local c = p$of_config;

	if ( p$of_config?$check_pred )
		return p$of_config$check_pred(p, r);

	if ( r$target == MONITOR && c$monitor )
		return T;

	if ( r$target == FORWARD && c$forward )
		return T;

	return F;
	}

function openflow_match_pred(p: PluginState, e: Entity, m: vector of OpenFlow::ofp_match) : vector of OpenFlow::ofp_match
	{
	if ( p$of_config?$match_pred )
		return p$of_config$match_pred(p, e, m);

	return m;
	}

function openflow_flow_mod_pred(p: PluginState, r: Rule, m: OpenFlow::ofp_flow_mod): OpenFlow::ofp_flow_mod
	{
	if ( p$of_config?$flow_mod_pred )
		return p$of_config$flow_mod_pred(p, r, m);

	return m;
	}

function determine_dl_type(s: subnet): count
	{
	local pdl = OpenFlow::ETH_IPv4;
	if ( is_v6_subnet(s) )
		pdl = OpenFlow::ETH_IPv6;

	return pdl;
	}

function determine_proto(p: port): count
	{
	local proto = OpenFlow::IP_TCP;
	if ( is_udp_port(p) )
		proto = OpenFlow::IP_UDP;
	else if ( is_icmp_port(p) )
		proto = OpenFlow::IP_ICMP;

	return proto;
	}

function entity_to_match(p: PluginState, e: Entity): vector of OpenFlow::ofp_match
	{
	local v : vector of OpenFlow::ofp_match = vector();

	if ( e$ty == CONNECTION )
		{
		v[|v|] = OpenFlow::match_conn(e$conn); # forward and...
		v[|v|] = OpenFlow::match_conn(e$conn, T); # reverse
		return openflow_match_pred(p, e, v);
		}

	if ( e$ty == MAC )
		{
		v[|v|] = OpenFlow::ofp_match(
			$dl_src=e$mac
		);
		v[|v|] = OpenFlow::ofp_match(
			$dl_dst=e$mac
		);

		return openflow_match_pred(p, e, v);
		}

	local dl_type = OpenFlow::ETH_IPv4;

	if ( e$ty == ADDRESS )
		{
		if ( is_v6_subnet(e$ip) )
			dl_type = OpenFlow::ETH_IPv6;

		v[|v|] = OpenFlow::ofp_match(
			$dl_type=dl_type,
			$nw_src=e$ip
		);

		v[|v|] = OpenFlow::ofp_match(
			$dl_type=dl_type,
			$nw_dst=e$ip
		);

		return openflow_match_pred(p, e, v);
		}

	local proto = OpenFlow::IP_TCP;

	if ( e$ty == FLOW )
		{
		local m = OpenFlow::ofp_match();
		local f = e$flow;

		if ( f?$src_m )
			m$dl_src=f$src_m;
		if ( f?$dst_m )
			m$dl_dst=f$dst_m;

		if ( f?$src_h )
			{
			m$dl_type = determine_dl_type(f$src_h);
			m$nw_src = f$src_h;
			}

		if ( f?$dst_h )
			{
			m$dl_type = determine_dl_type(f$dst_h);
			m$nw_dst = f$dst_h;
			}

		if ( f?$src_p )
			{
			m$nw_proto = determine_proto(f$src_p);
			m$tp_src = port_to_count(f$src_p);
			}

		if ( f?$dst_p )
			{
			m$nw_proto = determine_proto(f$dst_p);
			m$tp_dst = port_to_count(f$dst_p);
			}

		v[|v|] = m;

		return openflow_match_pred(p, e, v);
		}

	Reporter::error(fmt("Entity type %s not supported for openflow yet", cat(e$ty)));
	return openflow_match_pred(p, e, v);
	}

function openflow_rule_to_flow_mod(p: PluginState, r: Rule) : OpenFlow::ofp_flow_mod
	{
	local c = p$of_config;

	local flow_mod = OpenFlow::ofp_flow_mod(
		$cookie=OpenFlow::generate_cookie(r$cid*2), # leave one space for the cases in which we need two rules.
		$command=OpenFlow::OFPFC_ADD,
		$idle_timeout=c$idle_timeout,
		$priority=int_to_count(r$priority + c$priority_offset),
		$flags=OpenFlow::OFPFF_SEND_FLOW_REM # please notify us when flows are removed
	);

	if ( r?$expire )
		flow_mod$hard_timeout = double_to_count(interval_to_double(r$expire));
	if ( c?$table_id )
		flow_mod$table_id = c$table_id;

	if ( r$ty == DROP )
		{
		# default, nothing to do. We simply do not add an output port to the rule...
		}
	else if ( r$ty == WHITELIST )
		{
		# at the moment our interpretation of whitelist is to hand this off to the switches L2/L3 routing.
		flow_mod$actions$out_ports = vector(OpenFlow::OFPP_NORMAL);
		}
	else if ( r$ty == MODIFY )
		{
		# if no ports are given, just assume normal pipeline...
		flow_mod$actions$out_ports = vector(OpenFlow::OFPP_NORMAL);

		local mod = r$mod;
		if ( mod?$redirect_port )
			flow_mod$actions$out_ports = vector(mod$redirect_port);

		if ( mod?$src_h )
			flow_mod$actions$nw_src = mod$src_h;
		if ( mod?$dst_h )
			flow_mod$actions$nw_dst = mod$dst_h;
		if ( mod?$src_m )
			flow_mod$actions$dl_src = mod$src_m;
		if ( mod?$dst_m )
			flow_mod$actions$dl_dst = mod$dst_m;
		if ( mod?$src_p )
			flow_mod$actions$tp_src = mod$src_p;
		if ( mod?$dst_p )
			flow_mod$actions$tp_dst = mod$dst_p;
		}
	else if ( r$ty == REDIRECT )
		{
		# redirect to port c
		flow_mod$actions$out_ports = vector(r$c);
		}
	else
		{
		Reporter::error(fmt("Rule type %s not supported for openflow yet", cat(r$ty)));
		}

	return openflow_flow_mod_pred(p, r, flow_mod);
	}

function openflow_add_rule(p: PluginState, r: Rule) : bool
	{
	if ( ! openflow_check_rule(p, r) )
		return F;

	local flow_mod = openflow_rule_to_flow_mod(p, r);
	local matches = entity_to_match(p, r$entity);

	for ( i in matches )
		{
		if ( OpenFlow::flow_mod(p$of_controller, matches[i], flow_mod) )
			{
			of_messages[r$cid, flow_mod$command] = OfTable($p=p, $r=r);
			flow_mod = copy(flow_mod);
			++flow_mod$cookie;
			}
		else
			event rule_error(r, p, "Error while executing OpenFlow::flow_mod");
		}

	return T;
	}

function openflow_remove_rule(p: PluginState, r: Rule) : bool
	{
	if ( ! openflow_check_rule(p, r) )
		return F;

	local flow_mod: OpenFlow::ofp_flow_mod = [
		$cookie=OpenFlow::generate_cookie(r$cid),
		$command=OpenFlow::OFPFC_DELETE
	];

	if ( OpenFlow::flow_mod(p$of_controller, [], flow_mod) )
			of_messages[r$cid, flow_mod$command] = OfTable($p=p, $r=r);
	else
			{
			event rule_error(r, p, "Error while executing OpenFlow::flow_mod");
			return F;
			}

	# if this was an address or mac match, we also need to remove the reverse
	if ( r$entity$ty == ADDRESS || r$entity$ty == MAC )
		{
		local flow_mod_2 = copy(flow_mod);
		++flow_mod_2$cookie;
		OpenFlow::flow_mod(p$of_controller, [], flow_mod_2);
		}

	return T;
	}

event OpenFlow::flow_mod_success(match: OpenFlow::ofp_match, flow_mod: OpenFlow::ofp_flow_mod, msg: string) &priority=3
	{
	local id = OpenFlow::get_cookie_uid(flow_mod$cookie)/2;
	if ( [id, flow_mod$command] !in of_messages )
		return;

	local r = of_messages[id,flow_mod$command]$r;
	local p = of_messages[id,flow_mod$command]$p;
	local c = of_messages[id,flow_mod$command]$c;

	if ( r$entity$ty == ADDRESS || r$entity$ty == MAC )
		{
		++of_messages[id,flow_mod$command]$c;
		if ( of_messages[id,flow_mod$command]$c < 2 )
			return; # will do stuff once the second part arrives...
		}

	delete of_messages[id,flow_mod$command];

	if ( p$of_controller$supports_flow_removed )
		of_flows[id] = OfTable($p=p, $r=r);

	if ( flow_mod$command == OpenFlow::OFPFC_ADD )
		event Pacf::rule_added(r, p, msg);
	else if ( flow_mod$command == OpenFlow::OFPFC_DELETE || flow_mod$command == OpenFlow::OFPFC_DELETE_STRICT )
		event Pacf::rule_removed(r, p, msg);
	}

event OpenFlow::flow_mod_failure(match: OpenFlow::ofp_match, flow_mod: OpenFlow::ofp_flow_mod, msg: string) &priority=3
	{
	local id = OpenFlow::get_cookie_uid(flow_mod$cookie)/2;
	if ( [id, flow_mod$command] !in of_messages )
		return;

	local r = of_messages[id,flow_mod$command]$r;
	local p = of_messages[id,flow_mod$command]$p;
	delete of_messages[id,flow_mod$command];

	event Pacf::rule_error(r, p, msg);
	}

event OpenFlow::flow_removed(match: OpenFlow::ofp_match, cookie: count, priority: count, reason: count, duration_sec: count, idle_timeout: count, packet_count: count, byte_count: count)
	{
	local id = OpenFlow::get_cookie_uid(cookie)/2;
	if ( id !in of_flows )
		return;

	local rec = of_flows[id];
	local r = rec$r;
	local p = rec$p;

	if ( r$entity$ty == ADDRESS || r$entity$ty == MAC )
		{
		++of_flows[id]$c;
		if ( of_flows[id]$c < 2 )
			return; # will do stuff once the second part arrives...
		else
			event Pacf::rule_timeout(r, FlowInfo($duration=double_to_interval((rec$duration_sec+duration_sec)/2), $packet_count=packet_count+rec$packet_count, $byte_count=byte_count+rec$byte_count), p);

		return;
		}

	event Pacf::rule_timeout(r, FlowInfo($duration=double_to_interval(duration_sec+0.0), $packet_count=packet_count, $byte_count=byte_count), p);
	}

global openflow_plugin = Plugin(
	$name=openflow_name,
	$can_expire = T,
#	$init = openflow_init,
#	$done = openflow_done,
	$add_rule = openflow_add_rule,
	$remove_rule = openflow_remove_rule
#	$transaction_begin = openflow_transaction_begin,
#	$transaction_end = openflow_transaction_end
	);

function create_openflow(controller: OpenFlow::Controller, config: OfConfig &default=[]) : PluginState
	{
	local p: PluginState = [$plugin=openflow_plugin, $of_controller=controller, $of_config=config];

	return p;
	}
