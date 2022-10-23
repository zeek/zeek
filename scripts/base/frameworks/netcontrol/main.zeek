##! Zeek's NetControl framework.
##!
##! This plugin-based framework allows to control the traffic that Zeek monitors
##! as well as, if having access to the forwarding path, the traffic the network
##! forwards. By default, the framework lets everything through, to both Zeek
##! itself as well as on the network. Scripts can then add rules to impose
##! restrictions on entities, such as specific connections or IP addresses.
##!
##! This framework has two APIs: a high-level and low-level. The high-level API
##! provides convenience functions for a set of common operations. The
##! low-level API provides full flexibility.

@load ./plugin
@load ./types

module NetControl;

export {
	## The framework's logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	# ###
	# ###  Generic functions and events.
	# ###

	## Activates a plugin.
	##
	## p: The plugin to activate.
	##
	## priority: The higher the priority, the earlier this plugin will be checked
	##           whether it supports an operation, relative to other plugins.
	global activate: function(p: PluginState, priority: int);

	## Event that is used to initialize plugins. Place all plugin initialization
	## related functionality in this event.
	global NetControl::init: event();

	## Event that is raised once all plugins activated in ``NetControl::init``
	## have finished their initialization.
	global NetControl::init_done: event();

	# ###
	# ### High-level API.
	# ###

	# ### Note - other high level primitives are in catch-and-release.zeek,
	# ### shunt.zeek and drop.zeek

	## Allows all traffic involving a specific IP address to be forwarded.
	##
	## a: The address to be whitelisted.
	##
	## t: How long to whitelist it, with 0 being indefinitely.
	##
	## location: An optional string describing whitelist was triddered.
	##
	## Returns: The id of the inserted rule on success and zero on failure.
	global whitelist_address: function(a: addr, t: interval, location: string &default="") : string;

	## Allows all traffic involving a specific IP subnet to be forwarded.
	##
	## s: The subnet to be whitelisted.
	##
	## t: How long to whitelist it, with 0 being indefinitely.
	##
	## location: An optional string describing whitelist was triddered.
	##
	## Returns: The id of the inserted rule on success and zero on failure.
	global whitelist_subnet: function(s: subnet, t: interval, location: string &default="") : string;

	## Redirects a uni-directional flow to another port.
	##
	## f: The flow to redirect.
	##
	## out_port: Port to redirect the flow to.
	##
	## t: How long to leave the redirect in place, with 0 being indefinitely.
	##
	## location: An optional string describing where the redirect was triggered.
	##
	## Returns: The id of the inserted rule on success and zero on failure.
	global redirect_flow: function(f: flow_id, out_port: count, t: interval, location: string &default="") : string;

	## Quarantines a host. This requires a special quarantine server, which runs a HTTP server explaining
	## the quarantine and a DNS server which resolves all requests to the quarantine server. DNS queries
	## from the host to the network DNS server will be rewritten and will be sent to the quarantine server
	## instead. Only http communication infected to quarantinehost is allowed. All other network communication
	## is blocked.
	##
	## infected: the host to quarantine.
	##
	## dns: the network dns server.
	##
	## quarantine: the quarantine server running a dns and a web server.
	##
	## t: how long to leave the quarantine in place.
	##
	## Returns: Vector of inserted rules on success, empty list on failure.
	global quarantine_host: function(infected: addr, dns: addr, quarantine: addr, t: interval, location: string &default="") : vector of string;

	## Flushes all state by calling :zeek:see:`NetControl::remove_rule` on all currently active rules.
	global clear: function();

	# ###
	# ### Low-level API.
	# ###

	###### Manipulation of rules.

	## Installs a rule.
	##
	## r: The rule to install.
	##
	## Returns: If successful, returns an ID string unique to the rule that can
	##          later be used to refer to it. If unsuccessful, returns an empty
	##          string. The ID is also assigned to ``r$id``. Note that
	##          "successful" means "a plugin knew how to handle the rule", it
	##          doesn't necessarily mean that it was indeed successfully put in
	##          place, because that might happen asynchronously and thus fail
	##          only later.
	global add_rule: function(r: Rule) : string;

	## Removes a rule.
	##
	## id: The rule to remove, specified as the ID returned by :zeek:see:`NetControl::add_rule`.
	##
	## reason: Optional string argument giving information on why the rule was removed.
	##
	## Returns: True if successful, the relevant plugin indicated that it knew
	##          how to handle the removal. Note that again "success" means the
	##          plugin accepted the removal. It might still fail to put it
	##          into effect, as that might happen asynchronously and thus go
	##          wrong at that point.
	global remove_rule: function(id: string, reason: string &default="") : bool;

	## Deletes a rule without removing it from the backends to which it has been
	## added before. This means that no messages will be sent to the switches to which
	## the rule has been added; if it is not removed from them by a separate mechanism,
	## it will stay installed and not be removed later.
	##
	## id: The rule to delete, specified as the ID returned by :zeek:see:`NetControl::add_rule`.
	##
	## reason: Optional string argument giving information on why the rule was deleted.
	##
	## Returns: True if removal is successful, or sent to manager.
	##          False if the rule could not be found.
	global delete_rule: function(id: string, reason: string &default="") : bool;

	## Searches all rules affecting a certain IP address.
	##
	## This function works on both the manager and workers of a cluster. Note that on
	## the worker, the internal rule variables (starting with _) will not reflect the
	## current state.
	##
	## ip: The ip address to search for.
	##
	## Returns: vector of all rules affecting the IP address.
	global find_rules_addr: function(ip: addr) : vector of Rule;

	## Searches all rules affecting a certain subnet.
	##
	## A rule affects a subnet, if it covers the whole subnet. Note especially that
	## this function will not reveal all rules that are covered by a subnet.
	##
	## For example, a search for 192.168.17.0/8 will reveal a rule that exists for
	## 192.168.0.0/16, since this rule affects the subnet. However, it will not reveal
	## a more specific rule for 192.168.17.1/32, which does not directy affect the whole
	## subnet.
	##
	## This function works on both the manager and workers of a cluster. Note that on
	## the worker, the internal rule variables (starting with _) will not reflect the
	## current state.
	##
	## sn: The subnet to search for.
	##
	## Returns: vector of all rules affecting the subnet.
	global find_rules_subnet: function(sn: subnet) : vector of Rule;

	###### Asynchronous feedback on rules.

	## Confirms that a rule was put in place by a plugin.
	##
	## r: The rule now in place.
	##
	## p: The state for the plugin that put it into place.
	##
	## msg: An optional informational message by the plugin.
	global rule_added: event(r: Rule, p: PluginState, msg: string &default="");

	## Signals that a rule that was supposed to be put in place was already
	## existing at the specified plugin. Rules that already have been existing
	## continue to be tracked like normal, but no timeout calls will be sent
	## to the specified plugins. Removal of the rule from the hardware can
	## still be forced by manually issuing a remove_rule call.
	##
	## r: The rule that was already in place.
	##
	## p: The plugin that reported that the rule already was in place.
	##
	## msg: An optional informational message by the plugin.
	global rule_exists: event(r: Rule, p: PluginState, msg: string &default="");

	## Reports that a plugin reports a rule was removed due to a
	## remove_rule function call.
	##
	## r: The rule now removed.
	##
	## p: The state for the plugin that had the rule in place and now
	##    removed it.
	##
	## msg: An optional informational message by the plugin.
	global rule_removed: event(r: Rule, p: PluginState, msg: string &default="");

	## Reports that a rule was removed from a plugin due to a timeout.
	##
	## r: The rule now removed.
	##
	## i: Additional flow information, if supported by the protocol.
	##
	## p: The state for the plugin that had the rule in place and now
	##    removed it.
	##
	## msg: An optional informational message by the plugin.
	global rule_timeout: event(r: Rule, i: FlowInfo, p: PluginState);

	## Reports an error when operating on a rule.
	##
	## r: The rule that encountered an error.
	##
	## p: The state for the plugin that reported the error.
	##
	## msg: An optional informational message by the plugin.
	global rule_error: event(r: Rule, p: PluginState, msg: string &default="");

	## This event is raised when a new rule is created by the NetControl framework
	## due to a call to add_rule. From this moment, until the rule_destroyed event
	## is raised, the rule is tracked internally by the NetControl framework.
	##
	## Note that this event does not mean that a rule was successfully added by
	## any backend; it just means that the rule has been accepted and addition
	## to the specified backend is queued. To get information when rules are actually
	## installed by the hardware, use the rule_added, rule_exists, rule_removed, rule_timeout
	## and rule_error events.
	global rule_new: event(r: Rule);

	## This event is raised when a rule is deleted from the NetControl framework,
	## because it is no longer in use. This can be caused by the fact that a rule
	## was removed by all plugins to which it was added, by the fact that it timed out
	## or due to rule errors.
	##
	## To get the cause of a rule remove, catch the rule_removed, rule_timeout and
	## rule_error events.
	global rule_destroyed: event(r: Rule);

	## Hook that allows the modification of rules passed to add_rule before they
	## are passed on to the plugins. If one of the hooks uses break, the rule is
	## ignored and not passed on to any plugin.
	##
	## r: The rule to be added.
	global NetControl::rule_policy: hook(r: Rule);

	##### Plugin functions

	## Function called by plugins once they finished their activation. After all
	## plugins defined in zeek_init finished to activate, rules will start to be sent
	## to the plugins. Rules that scripts try to set before the backends are ready
	## will be discarded.
	global plugin_activated: function(p: PluginState);

	## Type of an entry in the NetControl log.
	type InfoCategory: enum {
		## A log entry reflecting a framework message.
		MESSAGE,
		## A log entry reflecting a framework message.
		ERROR,
		## A log entry about a rule.
		RULE
	};

	## State of an entry in the NetControl log.
	type InfoState: enum {
		REQUESTED, ##< The request to add/remove a rule was sent to the respective backend.
		SUCCEEDED, ##< A rule was successfully added by a backend.
		EXISTS, ##< A backend reported that a rule was already existing.
		FAILED, ##< A rule addition failed.
		REMOVED, ##< A rule was successfully removed by a backend.
		TIMEOUT, ##< A rule timeout was triggered by the NetControl framework or a backend.
	};

	## The record type defining the column fields of the NetControl log.
	type Info: record {
		## Time at which the recorded activity occurred.
		ts: time		&log;
		## ID of the rule; unique during each Zeek run.
		rule_id: string  &log &optional;
		## Type of the log entry.
		category: InfoCategory	&log &optional;
		## The command the log entry is about.
		cmd: string	&log &optional;
		## State the log entry reflects.
		state: InfoState	&log &optional;
		## String describing an action the entry is about.
		action: string		&log &optional;
		## The target type of the action.
		target: TargetType	&log &optional;
		## Type of the entity the log entry is about.
		entity_type: string		&log &optional;
		## String describing the entity the log entry is about.
		entity: string		&log &optional;
		## String describing the optional modification of the entry (e.h. redirect)
		mod: string		&log &optional;
		## String with an additional message.
		msg: string		&log &optional;
		## Number describing the priority of the log entry.
		priority: int &log &optional;
		## Expiry time of the log entry.
		expire: interval &log &optional;
		## Location where the underlying action was triggered.
		location: string	&log &optional;
		## Plugin triggering the log entry.
		plugin: string		&log &optional;
	};

	## Event that can be handled to access the :zeek:type:`NetControl::Info`
	## record as it is sent on to the logging framework.
	global log_netcontrol: event(rec: Info);
}

redef record Rule += {
	## Internally set to the plugins handling the rule.
	_plugin_ids: set[count] &default=count_set();
	## Internally set to the plugins on which the rule is currently active.
	_active_plugin_ids: set[count] &default=count_set();
	## Internally set to plugins where the rule should not be removed upon timeout.
	_no_expire_plugins: set[count] &default=count_set();
	## Track if the rule was added successfully by all responsible plugins.
	_added: bool &default=F;
};

# Variable tracking the state of plugin activation. Once all plugins that
# have been added in zeek_init are activated, this will switch to T and
# the event NetControl::init_done will be raised.
global plugins_active: bool = F;

# Set to true at the end of zeek_init (with very low priority).
# Used to track when plugin activation could potentially be finished
global zeek_init_done: bool = F;

# The counters that are used to generate the rule and plugin IDs
global rule_counter: count = 1;
global plugin_counter: count = 1;

# List of the currently active plugins
global plugins: vector of PluginState;
global plugin_ids: table[count] of PluginState;

# These tables hold information about rules.
global rules: table[string] of Rule; # Rules indexed by id and cid

# All rules that apply to a certain subnet/IP address.
global rules_by_subnets: table[subnet] of set[string];

# Rules pertaining to a specific entity.
# There always only can be one rule of each type for one entity.
global rule_entities: table[Entity, RuleType] of Rule;

event zeek_init() &priority=5
	{
	Log::create_stream(NetControl::LOG, [$columns=Info, $ev=log_netcontrol, $path="netcontrol", $policy=log_policy]);
	}

function entity_to_info(info: Info, e: Entity)
	{
	info$entity_type = fmt("%s", e$ty);

	switch ( e$ty ) {
		case ADDRESS:
			info$entity = fmt("%s", e$ip);
			break;

		case CONNECTION:
			info$entity = fmt("%s/%d<->%s/%d",
					  e$conn$orig_h, e$conn$orig_p,
					  e$conn$resp_h, e$conn$resp_p);
			break;

		case FLOW:
			local ffrom_ip = "*";
			local ffrom_port = "*";
			local fto_ip = "*";
			local fto_port = "*";
			local ffrom_mac = "*";
			local fto_mac = "*";
			if ( e$flow?$src_h )
				ffrom_ip = cat(e$flow$src_h);
			if ( e$flow?$src_p )
				ffrom_port = fmt("%d", e$flow$src_p);
			if ( e$flow?$dst_h )
				fto_ip = cat(e$flow$dst_h);
			if ( e$flow?$dst_p )
				fto_port = fmt("%d", e$flow$dst_p);
			info$entity = fmt("%s/%s->%s/%s",
					  ffrom_ip, ffrom_port,
					  fto_ip, fto_port);
			if ( e$flow?$src_m || e$flow?$dst_m )
				{
				if ( e$flow?$src_m )
					ffrom_mac = e$flow$src_m;
				if ( e$flow?$dst_m )
					fto_mac = e$flow$dst_m;

				info$entity = fmt("%s (%s->%s)", info$entity, ffrom_mac, fto_mac);
				}
			break;

		case MAC:
			info$entity = e$mac;
			break;

		default:
			info$entity = "<unknown entity type>";
			break;
		}
	}

function rule_to_info(info: Info, r: Rule)
	{
	info$action = fmt("%s", r$ty);
	info$target = r$target;
	info$rule_id = r$id;
	info$expire = r$expire;
	info$priority = r$priority;

	if ( r?$location && r$location != "" )
		info$location = r$location;

	if ( r$ty == REDIRECT )
		info$mod = fmt("-> %d", r$out_port);

	if ( r$ty == MODIFY )
		{
		local mfrom_ip = "_";
		local mfrom_port = "_";
		local mto_ip = "_";
		local mto_port = "_";
		local mfrom_mac = "_";
		local mto_mac = "_";
		if ( r$mod?$src_h )
			mfrom_ip = cat(r$mod$src_h);
		if ( r$mod?$src_p )
			mfrom_port = fmt("%d", r$mod$src_p);
		if ( r$mod?$dst_h )
			mto_ip = cat(r$mod$dst_h);
		if ( r$mod?$dst_p )
			mto_port = fmt("%d", r$mod$dst_p);

		if ( r$mod?$src_m )
			mfrom_mac = r$mod$src_m;
		if ( r$mod?$dst_m )
			mto_mac = r$mod$dst_m;

		info$mod = fmt("Src: %s/%s (%s) Dst: %s/%s (%s)",
			mfrom_ip, mfrom_port, mfrom_mac, mto_ip, mto_port, mto_mac);

		if ( r$mod?$redirect_port )
			info$mod = fmt("%s -> %d", info$mod, r$mod$redirect_port);

		}

	entity_to_info(info, r$entity);
	}

function log_msg(msg: string, p: PluginState)
	{
	Log::write(LOG, [$ts=network_time(), $category=MESSAGE, $msg=msg, $plugin=p$plugin$name(p)]);
	}

function log_error(msg: string, p: PluginState)
	{
	Log::write(LOG, [$ts=network_time(), $category=ERROR, $msg=msg, $plugin=p$plugin$name(p)]);
	}

function log_msg_no_plugin(msg: string)
	{
	Log::write(LOG, [$ts=network_time(), $category=MESSAGE, $msg=msg]);
	}

function log_rule(r: Rule, cmd: string, state: InfoState, p: PluginState, msg: string &default="")
	{
	local info: Info = [$ts=network_time()];
	info$category = RULE;
	info$cmd = cmd;
	info$state = state;
	info$plugin = p$plugin$name(p);
	if ( msg != "" )
		info$msg = msg;

	rule_to_info(info, r);

	Log::write(LOG, info);
	}

function log_rule_error(r: Rule, msg: string, p: PluginState)
	{
	local info: Info = [$ts=network_time(), $category=ERROR, $msg=msg, $plugin=p$plugin$name(p)];
	rule_to_info(info, r);
	Log::write(LOG, info);
	}

function log_rule_no_plugin(r: Rule, state: InfoState, msg: string)
	{
	local info: Info  = [$ts=network_time()];
	info$category = RULE;
	info$state = state;
	info$msg = msg;

	rule_to_info(info, r);

	Log::write(LOG, info);
	}

function whitelist_address(a: addr, t: interval, location: string &default="") : string
	{
	local e: Entity = [$ty=ADDRESS, $ip=addr_to_subnet(a)];
	local r: Rule = [$ty=WHITELIST, $priority=whitelist_priority, $target=FORWARD, $entity=e, $expire=t, $location=location];

	return add_rule(r);
	}

function whitelist_subnet(s: subnet, t: interval, location: string &default="") : string
	{
	local e: Entity = [$ty=ADDRESS, $ip=s];
	local r: Rule = [$ty=WHITELIST, $priority=whitelist_priority, $target=FORWARD, $entity=e, $expire=t, $location=location];

	return add_rule(r);
	}


function redirect_flow(f: flow_id, out_port: count, t: interval, location: string &default="") : string
	{
	local flow = NetControl::Flow(
		$src_h=addr_to_subnet(f$src_h),
		$src_p=f$src_p,
		$dst_h=addr_to_subnet(f$dst_h),
		$dst_p=f$dst_p
	);
	local e: Entity = [$ty=FLOW, $flow=flow];
	local r: Rule = [$ty=REDIRECT, $target=FORWARD, $entity=e, $expire=t, $location=location, $out_port=out_port];

	return add_rule(r);
	}

function quarantine_host(infected: addr, dns: addr, quarantine: addr, t: interval, location: string &default="") : vector of string
	{
	local orules: vector of string = vector();
	local edrop: Entity = [$ty=FLOW, $flow=Flow($src_h=addr_to_subnet(infected))];
	local rdrop: Rule = [$ty=DROP, $target=FORWARD, $entity=edrop, $expire=t, $location=location];
	orules += add_rule(rdrop);

	local todnse: Entity = [$ty=FLOW, $flow=Flow($src_h=addr_to_subnet(infected), $dst_h=addr_to_subnet(dns), $dst_p=53/udp)];
	local todnsr = Rule($ty=MODIFY, $target=FORWARD, $entity=todnse, $expire=t, $location=location, $mod=FlowMod($dst_h=quarantine), $priority=+5);
	orules += add_rule(todnsr);

	local fromdnse: Entity = [$ty=FLOW, $flow=Flow($src_h=addr_to_subnet(dns), $src_p=53/udp, $dst_h=addr_to_subnet(infected))];
	local fromdnsr = Rule($ty=MODIFY, $target=FORWARD, $entity=fromdnse, $expire=t, $location=location, $mod=FlowMod($src_h=dns), $priority=+5);
	orules += add_rule(fromdnsr);

	local wle: Entity = [$ty=FLOW, $flow=Flow($src_h=addr_to_subnet(infected), $dst_h=addr_to_subnet(quarantine), $dst_p=80/tcp)];
	local wlr = Rule($ty=WHITELIST, $target=FORWARD, $entity=wle, $expire=t, $location=location, $priority=+5);
	orules += add_rule(wlr);

	return orules;
	}

function check_plugins()
	{
	if ( plugins_active )
		return;

	local all_active = T;
	for ( i in plugins )
		{
		local p = plugins[i];
		if ( p$_activated == F )
			all_active = F;
		}

	if ( all_active )
		{
		plugins_active = T;

		# Skip log message if there are no plugins
		if ( |plugins| > 0 )
			log_msg_no_plugin("plugin initialization done");

		event NetControl::init_done();
		}
	}

function plugin_activated(p: PluginState)
	{
	local id = p$_id;
	if ( id !in plugin_ids )
		{
		log_error("unknown plugin activated", p);
		return;
		}

	# Suppress duplicate activation
	if ( plugin_ids[id]$_activated == T )
		return;

	plugin_ids[id]$_activated = T;
	log_msg("activation finished", p);

	if ( zeek_init_done )
		check_plugins();
	}

event zeek_init() &priority=-5
	{
	event NetControl::init();
	}

event NetControl::init() &priority=-20
	{
	zeek_init_done = T;

	check_plugins();

	if ( plugins_active == F )
		log_msg_no_plugin("waiting for plugins to initialize");
	}

# Low-level functions that only runs on the manager (or standalone) Zeek node.

function activate_impl(p: PluginState, priority: int)
	{
	p$_priority = priority;
	plugins += p;
	sort(plugins, function(p1: PluginState, p2: PluginState) : int { return p2$_priority - p1$_priority; });

	plugin_ids[plugin_counter] = p;
	p$_id = plugin_counter;
	++plugin_counter;

	# perform one-time initialization
	if ( p$plugin?$init )
		{
		log_msg(fmt("activating plugin with priority %d", priority), p);
		p$plugin$init(p);
		}
	else
		{
		# no initialization necessary, mark plugin as active right away
		plugin_activated(p);
		}

	}

function add_one_subnet_entry(s: subnet, r: Rule)
	{
	if ( ! check_subnet(s, rules_by_subnets) )
		rules_by_subnets[s] = set(r$id);
	else
		add rules_by_subnets[s][r$id];
	}

function add_subnet_entry(rule: Rule)
	{
	local e = rule$entity;
	if ( e$ty == ADDRESS )
		{
		add_one_subnet_entry(e$ip, rule);
		}
	else if ( e$ty == CONNECTION )
		{
		add_one_subnet_entry(addr_to_subnet(e$conn$orig_h), rule);
		add_one_subnet_entry(addr_to_subnet(e$conn$resp_h), rule);
		}
	else if ( e$ty == FLOW )
		{
		if ( e$flow?$src_h )
			add_one_subnet_entry(e$flow$src_h, rule);
		if ( e$flow?$dst_h )
			add_one_subnet_entry(e$flow$dst_h, rule);
		}
	}

function remove_one_subnet_entry(s: subnet, r: Rule)
	{
	if ( ! check_subnet(s, rules_by_subnets) )
		return;

	if ( r$id !in rules_by_subnets[s] )
		return;

	delete rules_by_subnets[s][r$id];
	if ( |rules_by_subnets[s]| == 0 )
		delete rules_by_subnets[s];
	}

function remove_subnet_entry(rule: Rule)
	{
	local e = rule$entity;
	if ( e$ty == ADDRESS )
		{
		remove_one_subnet_entry(e$ip, rule);
		}
	else if ( e$ty == CONNECTION )
		{
		remove_one_subnet_entry(addr_to_subnet(e$conn$orig_h), rule);
		remove_one_subnet_entry(addr_to_subnet(e$conn$resp_h), rule);
		}
	else if ( e$ty == FLOW )
		{
		if ( e$flow?$src_h )
			remove_one_subnet_entry(e$flow$src_h, rule);
		if ( e$flow?$dst_h )
			remove_one_subnet_entry(e$flow$dst_h, rule);
		}
	}

function find_rules_subnet(sn: subnet) : vector of Rule
	{
	local ret: vector of Rule = vector();

	local matches = matching_subnets(sn, rules_by_subnets);

	for ( m in matches )
		{
		local sn_entry = matches[m];
		local rule_ids = rules_by_subnets[sn_entry];
		for ( rule_id in rule_ids )
			{
			if ( rule_id in rules )
				ret += rules[rule_id];
			else
				Reporter::error("find_rules_subnet - internal data structure error, missing rule");
			}
		}

		return ret;
	}

function find_rules_addr(ip: addr) : vector of Rule
	{
	return find_rules_subnet(addr_to_subnet(ip));
	}

function add_rule_impl(rule: Rule) : string
	{
	if ( ! plugins_active )
		{
		log_rule_no_plugin(rule, FAILED, "plugins not initialized yet");
		return "";
		}

	rule$cid = ++rule_counter; # numeric id that can be used by plugins for their rules.

	if ( ! rule?$id || rule$id == "" )
		rule$id = cat(rule$cid);

	if ( ! hook NetControl::rule_policy(rule) )
		return "";

	if ( [rule$entity, rule$ty] in rule_entities )
		{
		log_rule_no_plugin(rule, FAILED, "discarded duplicate insertion");
		return "";
		}

	local accepted = F;
	local priority: int = +0;

	for ( i in plugins )
		{
		local p = plugins[i];

		if ( p$_activated == F )
			next;

		# in this case, rule was accepted by earlier plugin and this plugin has a lower
		# priority. Abort and do not send there...
		if ( accepted == T && p$_priority != priority )
			break;

		if ( p$plugin$add_rule(p, rule) )
			{
			accepted = T;
			priority = p$_priority;
			log_rule(rule, "ADD", REQUESTED, p);

			add rule$_plugin_ids[p$_id];
			}
		}

	if ( accepted )
		{
		rules[rule$id] = rule;
		rule_entities[rule$entity, rule$ty] = rule;

		add_subnet_entry(rule);

		event NetControl::rule_new(rule);

		return rule$id;
		}

	log_rule_no_plugin(rule, FAILED, "not supported");
	return "";
	}

function rule_cleanup(r: Rule)
	{
	if ( |r$_active_plugin_ids| > 0 )
		return;

	remove_subnet_entry(r);

	delete rule_entities[r$entity, r$ty];
	delete rules[r$id];

	event NetControl::rule_destroyed(r);
	}

function delete_rule_impl(id: string, reason: string): bool
	{
	if ( id !in rules )
		{
		Reporter::error(fmt("Rule %s does not exist in NetControl::delete_rule", id));
		return F;
		}

	local rule = rules[id];

	rule$_active_plugin_ids = set();

	rule_cleanup(rule);
	if ( reason != "" )
		log_rule_no_plugin(rule, REMOVED, fmt("delete_rule: %s", reason));
	else
		log_rule_no_plugin(rule, REMOVED, "delete_rule");

	return T;
	}

function remove_rule_plugin(r: Rule, p: PluginState, reason: string &default=""): bool
	{
	local success = T;

	if ( ! p$plugin$remove_rule(p, r, reason) )
		{
		# still continue and send to other plugins
		if ( reason != "" )
			log_rule_error(r, fmt("remove failed (original reason: %s)", reason), p);
		else
			log_rule_error(r, "remove failed", p);
		success = F;
		}
		else
		{
		log_rule(r, "REMOVE", REQUESTED, p, reason);
		}

	return success;
	}

function remove_rule_impl(id: string, reason: string) : bool
	{
	if ( id !in rules )
		{
		Reporter::error(fmt("Rule %s does not exist in NetControl::remove_rule", id));
		return F;
		}

	local r = rules[id];

	local success = T;
	for ( plugin_id in r$_active_plugin_ids )
		{
		local p = plugin_ids[plugin_id];
		success = remove_rule_plugin(r, p, reason);
		}

	return success;
	}

function rule_expire_impl(r: Rule, p: PluginState) &priority=-5 &is_used
	{
	# do not emit timeout events on shutdown
	if ( zeek_is_terminating() )
		return;

	if ( r$id !in rules )
		# Removed already.
		return;

	local rule = rules[r$id];

	if ( p$_id in rule$_no_expire_plugins )
		{
		# in this case - don't log anything, just remove the plugin from the rule
		# and cleanup
		delete rule$_active_plugin_ids[p$_id];
		delete rule$_no_expire_plugins[p$_id];
		rule_cleanup(rule);
		}
	else
		event NetControl::rule_timeout(r, FlowInfo(), p); # timeout implementation will handle the removal
	}

function rule_added_impl(r: Rule, p: PluginState, exists: bool, msg: string &default="") &is_used
	{
	if ( r$id !in rules )
		{
		log_rule_error(r, "Addition of unknown rule", p);
		return;
		}

	# use our version to prevent operating on copies.
	local rule = rules[r$id];
	if ( p$_id !in rule$_plugin_ids )
		{
		log_rule_error(rule, "Rule added to non-responsible plugin", p);
		return;
		}

	# The rule was already existing on the backend. Mark this so we don't timeout
	# it on this backend.
	if ( exists )
		{
		add rule$_no_expire_plugins[p$_id];
		log_rule(r, "ADD", EXISTS, p, msg);
		}
	else
		log_rule(r, "ADD", SUCCEEDED, p, msg);

	add rule$_active_plugin_ids[p$_id];
	if ( |rule$_plugin_ids| == |rule$_active_plugin_ids| )
		{
		# rule was completely added.
		rule$_added = T;
		}
	}

function rule_removed_impl(r: Rule, p: PluginState, msg: string &default="") &is_used
	{
	if ( r$id !in rules )
		{
		log_rule_error(r, "Removal of non-existing rule", p);
		return;
		}

	# use our version to prevent operating on copies.
	local rule = rules[r$id];

	if ( p$_id !in rule$_plugin_ids )
		{
		log_rule_error(r, "Removed from non-assigned plugin", p);
		return;
		}

	if ( p$_id in rule$_active_plugin_ids )
		{
		delete rule$_active_plugin_ids[p$_id];
		}

	log_rule(rule, "REMOVE", SUCCEEDED, p, msg);
	rule_cleanup(rule);
	}

function rule_timeout_impl(r: Rule, i: FlowInfo, p: PluginState) &is_used
	{
	if ( r$id !in rules )
		{
		log_rule_error(r, "Timeout of non-existing rule", p);
		return;
		}

	local rule = rules[r$id];

	local msg = "";
	if ( i?$packet_count )
		msg = fmt("Packets: %d", i$packet_count);
	if ( i?$byte_count )
		{
		if ( msg != "" )
			msg = msg + " ";
		msg = fmt("%sBytes: %s", msg, i$byte_count);
		}

	log_rule(rule, "EXPIRE", TIMEOUT, p, msg);

	if ( ! p$plugin$can_expire )
		{
		# in this case, we actually have to delete the rule and the timeout
		# call just originated locally
		remove_rule_plugin(rule, p);
		return;
		}

	if ( p$_id !in rule$_plugin_ids )
		{
		log_rule_error(r, "Timeout from non-assigned plugin", p);
		return;
		}

	if ( p$_id in rule$_active_plugin_ids )
		{
		delete rule$_active_plugin_ids[p$_id];
		}

	rule_cleanup(rule);
	}

function rule_error_impl(r: Rule, p: PluginState, msg: string &default="") &is_used
	{
	if ( r$id !in rules )
		{
		log_rule_error(r, "Error of non-existing rule", p);
		return;
		}

	local rule = rules[r$id];

	log_rule_error(rule, msg, p);

	# Remove the plugin both from active and all plugins of the rule. If there
	# are no plugins left afterwards - delete it
	if ( p$_id !in rule$_plugin_ids )
		{
		log_rule_error(r, "Error from non-assigned plugin", p);
		return;
		}

	if ( p$_id in rule$_active_plugin_ids )
		{
		# error during removal. Let's pretend it worked.
		delete rule$_plugin_ids[p$_id];
		delete rule$_active_plugin_ids[p$_id];
		rule_cleanup(rule);
		}
	else
		{
		# error during insertion. Meh. If we are the only plugin, remove the rule again.
		# Otherwhise - keep it, minus us.
		delete rule$_plugin_ids[p$_id];
		if ( |rule$_plugin_ids| == 0 )
			{
			rule_cleanup(rule);
			}
		}
	}

function clear()
	{
	for ( id in rules )
		remove_rule(id);
	}
