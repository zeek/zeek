# Broker plugin for the pacf framework. Sends the raw data structures
# used in pacf on to Broker to allow for easy handling, e.g., of
# command-line scripts.

module Pacf;

@load ../plugin
@load base/frameworks/broker

export {
	## Instantiates the broker plugin.
	global create_broker: function(host: addr, host_port: port, topic: string, can_expire: bool &default=F) : PluginState;

	redef record PluginState += {
		## The broker topic used to send events to
		broker_topic: string &optional;
		## The ID of this broker instance - for the mapping to PluginStates
		broker_id: count &optional;
		## Broker host to connect to
		broker_host: addr &optional;
		## Broker port to connect to
		broker_port: port &optional;
	};

	global broker_add_rule: event(id: count, r: Rule);
	global broker_remove_rule: event(id: count, r: Rule);

	global broker_rule_added: event(id: count, r: Rule, msg: string);
	global broker_rule_removed: event(id: count, r: Rule, msg: string);
	global broker_rule_error: event(id: count, r: Rule, msg: string);
	global broker_rule_timeout: event(id: count, r: Rule, i: FlowInfo);
}

global pacf_broker_topics: set[string] = set();
global pacf_broker_id: table[count] of PluginState = table();
global pacf_broker_current_id: count = 0;

event Pacf::broker_rule_added(id: count, r: Rule, msg: string)
	{
	if ( id !in pacf_broker_id )
		{
		Reporter::error(fmt("Pacf broker plugin with id %d not found, aborting", id));
		return;
		}

	local p = pacf_broker_id[id];

	event Pacf::rule_added(r, p, msg);
	}

event Pacf::broker_rule_removed(id: count, r: Rule, msg: string)
	{
	if ( id !in pacf_broker_id )
		{
		Reporter::error(fmt("Pacf broker plugin with id %d not found, aborting", id));
		return;
		}

	local p = pacf_broker_id[id];

	event Pacf::rule_removed(r, p, msg);
	}

event Pacf::broker_rule_error(id: count, r: Rule, msg: string)
	{
	if ( id !in pacf_broker_id )
		{
		Reporter::error(fmt("Pacf broker plugin with id %d not found, aborting", id));
		return;
		}

	local p = pacf_broker_id[id];

	event Pacf::rule_error(r, p, msg);
	}

event Pacf::broker_rule_timeout(id: count, r: Rule, i: FlowInfo)
	{
	if ( id !in pacf_broker_id )
		{
		Reporter::error(fmt("Pacf broker plugin with id %d not found, aborting", id));
		return;
		}

	local p = pacf_broker_id[id];

	event Pacf::rule_timeout(r, i, p);
	}

function broker_name(p: PluginState) : string
	{
	return fmt("PACF Broker plugin - topic %s", p$broker_topic);
	}

function broker_add_rule_fun(p: PluginState, r: Rule) : bool
	{
	BrokerComm::event(p$broker_topic, BrokerComm::event_args(broker_add_rule, p$broker_id, r));
	return T;
	}

function broker_remove_rule_fun(p: PluginState, r: Rule) : bool
	{
	BrokerComm::event(p$broker_topic, BrokerComm::event_args(broker_remove_rule, p$broker_id, r));
	return T;
	}

function broker_init(p: PluginState)
	{
	BrokerComm::enable();
	BrokerComm::connect(cat(p$broker_host), p$broker_port, 1sec);
	BrokerComm::subscribe_to_events(p$broker_topic);
	}

global broker_plugin = Plugin(
	$name=broker_name,
	$can_expire = F,
	$add_rule = broker_add_rule_fun,
	$remove_rule = broker_remove_rule_fun,
	$init = broker_init
	);

global broker_plugin_can_expire = Plugin(
	$name=broker_name,
	$can_expire = T,
	$add_rule = broker_add_rule_fun,
	$remove_rule = broker_remove_rule_fun,
	$init = broker_init
	);

function create_broker(host: addr, host_port: port, topic: string, can_expire: bool &default=F) : PluginState
	{
	if ( topic in pacf_broker_topics )
		Reporter::warning(fmt("Topic %s was added to Pacf broker plugin twice. Possible duplication of commands", topic));
	else
		add pacf_broker_topics[topic];

	local plugin = broker_plugin;
	if ( can_expire )
		plugin = broker_plugin_can_expire;

	local p: PluginState = [$broker_host=host, $broker_port=host_port, $plugin=plugin, $broker_topic=topic, $broker_id=pacf_broker_current_id];

	pacf_broker_id[pacf_broker_current_id] = p;
	++pacf_broker_current_id;

	return p;
	}
