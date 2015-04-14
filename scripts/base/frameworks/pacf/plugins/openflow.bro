@load ../plugin
@load base/frameworks/openflow

module Pacf;

export {
	type OfConfig: record {
		monitor: bool &default=T;
		forward: bool &default=T;
		idle_timeout: count &default=60;
		table_id: count &optional;
	};

	redef record PluginState += {
		## OpenFlow controller for Pacf OpenFlow plugin
		of_controller: OpenFlow::Controller &optional;
		## OpenFlow configuration record that is passed on initialization
		of_config: OfConfig &optional;
	};

	## Instantiates an openflow plugin for the PACF framework.
	global create_openflow: function(controller: OpenFlow::Controller, config: OfConfig &default=[]) : PluginState;
}

function openflow_name(p: PluginState) : string
	{
	return fmt("Openflow - %s", p$of_controller$describe(p$of_controller$state));
	}

function openflow_check_rule(c: OfConfig, r: Rule) : bool
	{
	if ( r$target == MONITOR && c$monitor )
		return T;

	if ( r$target == FORWARD && c$forward )
		return T;

	return F;
	}

function entity_to_match(e: Entity): vector of OpenFlow::ofp_match
	{
	local v : vector of OpenFlow::ofp_match = vector();

	if ( e$ty == CONNECTION )
		{
		v[|v|] = OpenFlow::match_conn(e$conn); # forward and...
		v[|v|] = OpenFlow::match_conn(e$conn, T); # reverse
		return v;
		}

	local dl_type = OpenFlow::ETH_IPv4;

	if ( e$ty == ADDRESS || e$ty == RESPONDER || e$ty == ORIGINATOR )
		{
		if ( is_v6_subnet(e$ip) )
			dl_type = OpenFlow::ETH_IPv6;

		if ( e$ty == ADDRESS || e$ty == ORIGINATOR )
			v[|v|] = OpenFlow::ofp_match(
				$dl_type=dl_type,
				$nw_src=e$ip
			);

		if ( e$ty == ADDRESS || e$ty == RESPONDER )
			v[|v|] = OpenFlow::ofp_match(
				$dl_type=dl_type,
				$nw_dst=e$ip
			);

		return v;
		}

	local proto = OpenFlow::IP_TCP;

	if ( e$ty == FLOW )
		{
		if ( is_v6_addr(e$flow$src_h) )
			dl_type = OpenFlow::ETH_IPv6;

		if ( is_udp_port(e$flow$src_p) )
			proto = OpenFlow::IP_UDP;
		else if ( is_icmp_port(e$flow$src_p) )
			proto = OpenFlow::IP_ICMP;

		v[|v|] = OpenFlow::ofp_match(
			$dl_type=dl_type,
			$nw_proto=proto,
			$nw_src=addr_to_subnet(e$flow$src_h),
			$tp_src=e$flow$src_p,
			$nw_dst=addr_to_subnet(e$flow$dst_h),
			$tp_dst=e$flow$dst_p
		);
		return v;
		}

	Reporter::error(fmt("Entity type %s not supported for openflow yet", cat(e$ty)));
	return v;
	}

function openflow_add_rule(p: PluginState, r: Rule) : bool
	{
	local c = p$of_config;

	if ( ! openflow_check_rule(c, r) )
		return F;

	local flow_mod: OpenFlow::ofp_flow_mod = [
		$cookie=r$id,
		$command=OpenFlow::OFPFC_ADD,
		$idle_timeout=c$idle_timeout,
		$priority=int_to_count(r$priority)
	];

	if ( r?$expire )
		flow_mod$hard_timeout = double_to_count(interval_to_double(r$expire));
	if ( c?$table_id )
		flow_mod$table_id = c$table_id;

	local matches = entity_to_match(r$entity);

	for ( i in matches )
		{
		if ( ! OpenFlow::flow_mod(p$of_controller, matches[i], flow_mod) )
			event rule_error(r, p, "Error while executing OpenFlow::flow_mod");
		}

	return T;
	}

function openflow_remove_rule(p: PluginState, r: Rule) : bool
	{
	if ( ! openflow_check_rule(p$of_config, r) )
		return F;

	local flow_mod: OpenFlow::ofp_flow_mod = [
		$cookie=r$id,
		$command=OpenFlow::OFPFC_DELETE
	];

	OpenFlow::flow_mod(p$of_controller, [], flow_mod);

	return T;
	}

global openflow_plugin = Plugin(
	$name=openflow_name,
	$can_expire = T,
#	$init = openflow_init,
#	$done = openflow_done,
	$add_rule = openflow_add_rule,
	$remove_rule = openflow_remove_rule
#	$add_notification = openflow_add_notification,
#	$remove_notification = openflow_remove_notification,
#	$transaction_begin = openflow_transaction_begin,
#	$transaction_end = openflow_transaction_end
	);

function create_openflow(controller: OpenFlow::Controller, config: OfConfig &default=[]) : PluginState
	{
	local p: PluginState = [$plugin=openflow_plugin, $of_controller=controller, $of_config=config];

	return p;
	}
