##! Acld plugin for the netcontrol framework.

@load ../main
@load ../plugin
@load base/frameworks/broker

module NetControl;

export {
	type AclRule : record {
		command: string;
		cookie: count;
		arg: string;
		comment: string &optional;
	};

	type AcldConfig: record {
		## The acld topic to send events to.
		acld_topic: string;
		## Broker host to connect to.
		acld_host: addr;
		## Broker port to connect to.
		acld_port: port;
		## Do we accept rules for the monitor path? Default false.
		monitor: bool &default=F;
		## Do we accept rules for the forward path? Default true.
		forward: bool &default=T;

		## Predicate that is called on rule insertion or removal.
		##
		## p: Current plugin state.
		##
		## r: The rule to be inserted or removed.
		##
		## Returns: T if the rule can be handled by the current backend, F otherwise.
		check_pred: function(p: PluginState, r: Rule): bool &optional;
	};

	## Instantiates the acld plugin.
	global create_acld: function(config: AcldConfig) : PluginState;

	redef record PluginState += {
		acld_config: AcldConfig &optional;
		## The ID of this acld instance - for the mapping to PluginStates.
		acld_id: count &optional;
	};

	## Hook that is called after a rule is converted to an acld rule.
	## The hook may modify the rule before it is sent to acld.
	## Setting the acld command to F will cause the rule to be rejected
	## by the plugin.
	##
	## p: Current plugin state.
	##
	## r: The rule to be inserted or removed.
	##
	## ar: The acld rule to be inserted or removed.
	global NetControl::acld_rule_policy: hook(p: PluginState, r: Rule, ar: AclRule);

	## Events that are sent from us to Broker.
	global acld_add_rule: event(id: count, r: Rule, ar: AclRule);
	global acld_remove_rule: event(id: count, r: Rule, ar: AclRule);

	## Events that are sent from Broker to us.
	global acld_rule_added: event(id: count, r: Rule, msg: string);
	global acld_rule_removed: event(id: count, r: Rule, msg: string);
	global acld_rule_exists: event(id: count, r: Rule, msg: string);
	global acld_rule_error: event(id: count, r: Rule, msg: string);
}

global netcontrol_acld_peers: table[port, string] of PluginState;
global netcontrol_acld_topics: set[string] = set();
global netcontrol_acld_id: table[count] of PluginState = table();
global netcontrol_acld_current_id: count = 0;

const acld_add_to_remove: table[string] of string = {
	["drop"] = "restore",
	["addwhitelist"] = "remwhitelist",
	["blockhosthost"] = "restorehosthost",
	["droptcpport"] = "restoretcpport",
	["dropudpport"] = "restoreudpport",
	["droptcpdsthostport"] ="restoretcpdsthostport",
	["dropudpdsthostport"] ="restoreudpdsthostport",
	["permittcpdsthostport"] ="unpermittcpdsthostport",
	["permitudpdsthostport"] ="unpermitudpdsthostport",
	["nullzero"] ="nonullzero",
	["filter"]="nofilter",
};

event NetControl::acld_rule_added(id: count, r: Rule, msg: string)
	{
	if ( id !in netcontrol_acld_id )
		{
		Reporter::error(fmt("NetControl acld plugin with id %d not found, aborting", id));
		return;
		}

	local p = netcontrol_acld_id[id];

	event NetControl::rule_added(r, p, msg);
	}

event NetControl::acld_rule_exists(id: count, r: Rule, msg: string)
	{
	if ( id !in netcontrol_acld_id )
		{
		Reporter::error(fmt("NetControl acld plugin with id %d not found, aborting", id));
		return;
		}

	local p = netcontrol_acld_id[id];

	event NetControl::rule_exists(r, p, msg);
	}

event NetControl::acld_rule_removed(id: count, r: Rule, msg: string)
	{
	if ( id !in netcontrol_acld_id )
		{
		Reporter::error(fmt("NetControl acld plugin with id %d not found, aborting", id));
		return;
		}

	local p = netcontrol_acld_id[id];

	event NetControl::rule_removed(r, p, msg);
	}

event NetControl::acld_rule_error(id: count, r: Rule, msg: string)
	{
	if ( id !in netcontrol_acld_id )
		{
		Reporter::error(fmt("NetControl acld plugin with id %d not found, aborting", id));
		return;
		}

	local p = netcontrol_acld_id[id];

	event NetControl::rule_error(r, p, msg);
	}

function acld_name(p: PluginState) : string
	{
	return fmt("Acld-%s", p$acld_config$acld_topic);
	}

# check that subnet specifies an addr
function check_sn(sn: subnet) : bool
	{
	if ( is_v4_subnet(sn) && subnet_width(sn) == 32 )
		return T;
	if ( is_v6_subnet(sn) && subnet_width(sn) == 128 )
		return T;

	Reporter::error(fmt("Acld: rule_to_acl_rule was given a subnet that does not specify a distinct address where needed - %s", sn));
	return F;
	}

function rule_to_acl_rule(p: PluginState, r: Rule) : AclRule
	{
	local e = r$entity;

	local command: string = "";
	local arg: string = "";

	if ( e$ty == ADDRESS )
		{
		if ( r$ty == DROP )
			command = "drop";
		else if ( r$ty == WHITELIST )
			command = "addwhitelist";
		arg = cat(e$ip);
		}
	else if ( e$ty == FLOW )
		{
		local f = e$flow;
		if ( ( ! f?$src_h ) && ( ! f?$src_p ) && f?$dst_h && f?$dst_p && ( ! f?$src_m ) && ( ! f?$dst_m ) )
			{
			if ( !check_sn(f$dst_h) )
				command = ""; # invalid addr, do nothing
			else if ( is_tcp_port(f$dst_p) && r$ty == DROP )
				command = "droptcpdsthostport";
			else if ( is_tcp_port(f$dst_p) && r$ty == WHITELIST )
				command = "permittcpdsthostport";
			else if ( is_udp_port(f$dst_p) && r$ty == DROP)
				command = "dropucpdsthostport";
			else if ( is_udp_port(f$dst_p) && r$ty == WHITELIST)
				command = "permitucpdsthostport";

			arg = fmt("%s %d", subnet_to_addr(f$dst_h), f$dst_p);
			}
		else if ( f?$src_h && ( ! f?$src_p ) && f?$dst_h && ( ! f?$dst_p ) && ( ! f?$src_m ) && ( ! f?$dst_m ) )
			{
			if ( !check_sn(f$src_h) || !check_sn(f$dst_h) )
				command = "";
			else if ( r$ty == DROP )
				command = "blockhosthost";
			arg = fmt("%s %s", subnet_to_addr(f$src_h), subnet_to_addr(f$dst_h));
			}
		else if ( ( ! f?$src_h ) && ( ! f?$src_p ) && ( ! f?$dst_h ) && f?$dst_p && ( ! f?$src_m ) && ( ! f?$dst_m ) )
			{
			if ( is_tcp_port(f$dst_p) && r$ty == DROP )
				command = "droptcpport";
			else if ( is_udp_port(f$dst_p) && r$ty == DROP )
				command = "dropudpport";
			arg = fmt("%d", f$dst_p);
			}
		}

	local ar = AclRule($command=command, $cookie=r$cid, $arg=arg);
	if ( r?$location )
		ar$comment = r$location;

	hook NetControl::acld_rule_policy(p, r, ar);

	return ar;
	}

function acld_check_rule(p: PluginState, r: Rule) : bool
	{
	local c = p$acld_config;

	if ( p$acld_config?$check_pred )
		return p$acld_config$check_pred(p, r);

	if ( r$target == MONITOR && c$monitor )
		return T;

	if ( r$target == FORWARD && c$forward )
		return T;

	return F;
	}

function acld_add_rule_fun(p: PluginState, r: Rule) : bool
	{
	if ( ! acld_check_rule(p, r) )
		return F;

	local ar = rule_to_acl_rule(p, r);

	if ( ar$command == "" )
		return F;

	Broker::publish(p$acld_config$acld_topic, acld_add_rule, p$acld_id, r, ar);
	return T;
	}

function acld_remove_rule_fun(p: PluginState, r: Rule, reason: string) : bool
	{
	if ( ! acld_check_rule(p, r) )
		return F;

	local ar = rule_to_acl_rule(p, r);
	if ( ar$command in acld_add_to_remove )
		ar$command = acld_add_to_remove[ar$command];
	else
		return F;

	if ( reason != "" )
		{
		if ( ar?$comment )
			ar$comment = fmt("%s (%s)", reason, ar$comment);
		else
			ar$comment = reason;
		}

	Broker::publish(p$acld_config$acld_topic, acld_remove_rule, p$acld_id, r, ar);
	return T;
	}

function acld_init(p: PluginState)
	{
	Broker::subscribe(p$acld_config$acld_topic);
	Broker::peer(cat(p$acld_config$acld_host), p$acld_config$acld_port);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	local peer_address = cat(endpoint$network$address);
	local peer_port = endpoint$network$bound_port;
	if ( [peer_port, peer_address] !in netcontrol_acld_peers )
		# ok, this one was none of ours...
		return;

	local p = netcontrol_acld_peers[peer_port, peer_address];
	plugin_activated(p);
	}

global acld_plugin = Plugin(
	$name=acld_name,
	$can_expire = F,
	$add_rule = acld_add_rule_fun,
	$remove_rule = acld_remove_rule_fun,
	$init = acld_init
	);

function create_acld(config: AcldConfig) : PluginState
	{
	if ( config$acld_topic in netcontrol_acld_topics )
		Reporter::warning(fmt("Topic %s was added to NetControl acld plugin twice. Possible duplication of commands", config$acld_topic));
	else
		add netcontrol_acld_topics[config$acld_topic];

	local host = cat(config$acld_host);
	local p: PluginState = [$acld_config=config, $plugin=acld_plugin, $acld_id=netcontrol_acld_current_id];

	if ( [config$acld_port, host] in netcontrol_acld_peers )
		Reporter::warning(fmt("Peer %s:%s was added to NetControl acld plugin twice.", host, config$acld_port));
	else
		netcontrol_acld_peers[config$acld_port, host] = p;

	netcontrol_acld_id[netcontrol_acld_current_id] = p;
	++netcontrol_acld_current_id;

	return p;
	}
