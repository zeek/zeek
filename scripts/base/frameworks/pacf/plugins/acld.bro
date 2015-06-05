# Acld plugin for the pacf framework.

module Pacf;

@load ../plugin
@load base/frameworks/broker

export {
	type AclRule : record {
		command: string;
		cookie: count;
		arg: string;
		comment: string &optional;
	};

	type AcldConfig: record {
		## The acld topic used to send events to
		acld_topic: string;
		## Broker host to connect to
		acld_host: addr;
		## Broker port to connect to
		acld_port: port;
		## Function that can decide weather to accept add request
		add_pred: function(p: PluginState, r: Rule, ar: AclRule): bool &optional &weaken;
	};

	## Instantiates the acld plugin.
	global create_acld: function(config: AcldConfig) : PluginState;	

	redef record PluginState += {
		acld_config: AcldConfig &optional;
		## The ID of this acld instance - for the mapping to PluginStates
		acld_id: count &optional;
	};

	global acld_add_rule: event(id: count, r: Rule, ar: AclRule);
	global acld_remove_rule: event(id: count, r: Rule, ar: AclRule);

	global acld_rule_added: event(id: count, r: Rule, msg: string);
	global acld_rule_removed: event(id: count, r: Rule, msg: string);
	global acld_rule_error: event(id: count, r: Rule, msg: string);
}

global pacf_acld_topics: set[string] = set();
global pacf_acld_id: table[count] of PluginState = table();
global pacf_acld_current_id: count = 0;

const acld_add_to_remove: table[string] of string = {
	["drop"] = "restore",
	["whitelist"] = "remwhitelist",
	["blockhosthost"] = "restorehosthost",
	["droptcpport"] = "restoretcpport",
	["dropudpport"] = "restoreudpport",
	["droptcpdsthostport"] ="restoretcpdsthostport",
	["dropudpdsthostport"] ="restoreudpdsthostport",
	["permittcpdsthostport"] ="unpermittcpdsthostport",
	["permitudpdsthostport"] ="unpermitudpdsthostport",
	["nullzero "] ="nonullzero"
};

event Pacf::acld_rule_added(id: count, r: Rule, msg: string)
	{
	if ( id !in pacf_acld_id )
		{
		Reporter::error(fmt("Pacf acld plugin with id %d not found, aborting", id));
		return;
		}

	local p = pacf_acld_id[id];

	event Pacf::rule_added(r, p, msg);
	}

event Pacf::acld_rule_removed(id: count, r: Rule, msg: string)
	{
	if ( id !in pacf_acld_id )
		{
		Reporter::error(fmt("Pacf acld plugin with id %d not found, aborting", id));
		return;
		}

	local p = pacf_acld_id[id];

	event Pacf::rule_removed(r, p, msg);
	}

event Pacf::acld_rule_error(id: count, r: Rule, msg: string)
	{
	if ( id !in pacf_acld_id )
		{
		Reporter::error(fmt("Pacf acld plugin with id %d not found, aborting", id));
		return;
		}

	local p = pacf_acld_id[id];

	event Pacf::rule_error(r, p, msg);
	}

function acld_name(p: PluginState) : string
	{
	return fmt("PACF acld plugin - using broker topic %s", p$acld_config$acld_topic);
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

function rule_to_acl_rule(r: Rule) : AclRule
	{
	local e = r$entity;

	local command: string = "";
	local arg: string = "";

	if ( e$ty == ADDRESS )
		{
		if ( r$ty == DROP )
			command = "drop";
		else if ( r$ty == WHITELIST )
			command = "whitelist";
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
	return ar;
	}

function acld_add_rule_fun(p: PluginState, r: Rule) : bool
	{
	local ar = rule_to_acl_rule(r);

	if ( p$acld_config?$add_pred )
		if ( ! p$acld_config$add_pred(p, r, ar) )
			return F;

	if ( ar$command == "" )
		return F;

	BrokerComm::event(p$acld_config$acld_topic, BrokerComm::event_args(acld_add_rule, p$acld_id, r, ar));
	return T;
	}

function acld_remove_rule_fun(p: PluginState, r: Rule) : bool
	{
	local ar = rule_to_acl_rule(r);
	if ( ar$command in acld_add_to_remove )
		ar$command = acld_add_to_remove[ar$command];
	else
		return F;

	BrokerComm::event(p$acld_config$acld_topic, BrokerComm::event_args(acld_remove_rule, p$acld_id, r, ar));
	return T;
	}

function acld_init(p: PluginState)
	{
	BrokerComm::enable();
	BrokerComm::connect(cat(p$acld_config$acld_host), p$acld_config$acld_port, 1sec);
	BrokerComm::subscribe_to_events(p$acld_config$acld_topic);
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
	if ( config$acld_topic in pacf_acld_topics )
		Reporter::warning(fmt("Topic %s was added to Pacf acld plugin twice. Possible duplication of commands", config$acld_topic));
	else
		add pacf_acld_topics[config$acld_topic];

	local p: PluginState = [$acld_config=config, $plugin=acld_plugin, $acld_id=pacf_acld_current_id];

	pacf_acld_id[pacf_acld_current_id] = p;
	++pacf_acld_current_id;

	return p;
	}

