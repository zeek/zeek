##! Broker plugin for the netcontrol framework. Sends the raw data structures
##! used in NetControl on to Broker to allow for easy handling, e.g., of
##! command-line scripts.

module NetControl;

@load ../main
@load ../plugin
@load base/frameworks/broker

@ifdef ( Broker::__enable )

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

global netcontrol_broker_peers: table[port, string] of PluginState;
global netcontrol_broker_topics: set[string] = set();
global netcontrol_broker_id: table[count] of PluginState = table();
global netcontrol_broker_current_id: count = 0;

event NetControl::broker_rule_added(id: count, r: Rule, msg: string)
	{
	if ( id !in netcontrol_broker_id )
		{
		Reporter::error(fmt("NetControl broker plugin with id %d not found, aborting", id));
		return;
		}

	local p = netcontrol_broker_id[id];

	event NetControl::rule_added(r, p, msg);
	}

event NetControl::broker_rule_removed(id: count, r: Rule, msg: string)
	{
	if ( id !in netcontrol_broker_id )
		{
		Reporter::error(fmt("NetControl broker plugin with id %d not found, aborting", id));
		return;
		}

	local p = netcontrol_broker_id[id];

	event NetControl::rule_removed(r, p, msg);
	}

event NetControl::broker_rule_error(id: count, r: Rule, msg: string)
	{
	if ( id !in netcontrol_broker_id )
		{
		Reporter::error(fmt("NetControl broker plugin with id %d not found, aborting", id));
		return;
		}

	local p = netcontrol_broker_id[id];

	event NetControl::rule_error(r, p, msg);
	}

event NetControl::broker_rule_timeout(id: count, r: Rule, i: FlowInfo)
	{
	if ( id !in netcontrol_broker_id )
		{
		Reporter::error(fmt("NetControl broker plugin with id %d not found, aborting", id));
		return;
		}

	local p = netcontrol_broker_id[id];

	event NetControl::rule_timeout(r, i, p);
	}

function broker_name(p: PluginState) : string
	{
	return fmt("Broker-%s", p$broker_topic);
	}

function broker_add_rule_fun(p: PluginState, r: Rule) : bool
	{
	Broker::send_event(p$broker_topic, Broker::event_args(broker_add_rule, p$broker_id, r));
	return T;
	}

function broker_remove_rule_fun(p: PluginState, r: Rule) : bool
	{
	Broker::send_event(p$broker_topic, Broker::event_args(broker_remove_rule, p$broker_id, r));
	return T;
	}

function broker_init(p: PluginState)
	{
	Broker::enable();
	Broker::connect(cat(p$broker_host), p$broker_port, 1sec);
	Broker::subscribe_to_events(p$broker_topic);
	}

event Broker::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
	{
	if ( [peer_port, peer_address] !in netcontrol_broker_peers )
		return;

	local p = netcontrol_broker_peers[peer_port, peer_address];
	plugin_activated(p);
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
	if ( topic in netcontrol_broker_topics )
		Reporter::warning(fmt("Topic %s was added to NetControl broker plugin twice. Possible duplication of commands", topic));
	else
		add netcontrol_broker_topics[topic];

	local plugin = broker_plugin;
	if ( can_expire )
		plugin = broker_plugin_can_expire;

	local p: PluginState = [$broker_host=host, $broker_port=host_port, $plugin=plugin, $broker_topic=topic, $broker_id=netcontrol_broker_current_id];

	if ( [host_port, cat(host)] in netcontrol_broker_peers )
		Reporter::warning(fmt("Peer %s:%s was added to NetControl broker plugin twice.", host, host_port));
	else
		netcontrol_broker_peers[host_port, cat(host)] = p;

	netcontrol_broker_id[netcontrol_broker_current_id] = p;
	++netcontrol_broker_current_id;

	return p;
	}

@endif
