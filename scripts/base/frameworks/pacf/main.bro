##! Bro's packet aquisition and control framework.
##!
##! This plugin-based framework allows to control the traffic that Bro monitors
##! as well as, if having access to the forwarding path, the traffic the network
##! forwards. By default, the framework lets evyerthing through, to both Bro
##! itself as well as on the network. Scripts can then add rules to impose
##! restrictions on entities, such as specific connections or IP addresses.
##!
##! This framework has two API: a high-level and low-level. The high-levem API
##! provides convinience functions for a set of common operations. The
##! low-level API provides full flexibility.

module Pacf;

@load ./plugin
@load ./types

export {
	## The framework's logging stream identifier.
	redef enum Log::ID += { LOG };

	# ###
	# ###  Generic functions.
	# ###

	# Activates a plugin.
	#
	# plugin: The plugin to acticate.
	#
	# priority: The higher the priority, the earlier this plugin will be checked
	# whether it supports an operation, relative to other plugins.
	global activate: function(p: PluginState, priority: int);

	# ###
	# ### High-level API.
	# ###

	## Stops all packets involving an IP address from being forwarded.
	##
	## a: The address to be dropped.
	##
	## t: How long to drop it, with 0 being indefinitly.
	##
	## location: An optional string describing where the drop was triggered.
	##
	## Returns: True if a plugin accepted the rule for carrying it out.
	global drop_address: function(a: addr, t: interval, location: string &default="") : bool;

	## Stops forwarding a uni-directional flow's packets to Bro.
	##
	## f: The flow to shunt.
	##
	## t: How long to leave the shunt in place, with 0 being indefinitly.
	##
	## location: An optional string describing where the shunt was triggered.
	##
	## Returns: True if a plugin accepted the rule for carrying it out.
	global shunt_flow: function(f: flow_id, t: interval, location: string &default="") : bool;

	## Removes all rules and notifications for an entity.
	##
	## e: The entity. Note that this will be directly to entities of existing
	## notifications and notifications, which must match exactly field by field.
	global reset: function(e: Entity);

	## Flushes all state.
	global clear: function();

	# ###
	# ### Low-level API.
	# ###

	###### Manipulation of rules.

	## Installs a rule.
	##
	## r: The rule to install.
	##
	## Returns: If succesful, returns an ID string unique to the rule that can later
	## be used to refer to it. If unsuccessful, returns an empty string. The ID is also
	## assigned to ``r$id``. Note that "successful" means "a plugin knew how to handle
	## the rule", it doesn't necessarily mean that it was indeed successfully put in
	## place, because that might happen asynchronously and thus fail only later.
	global add_rule: function(r: Rule) : string;

	## Removes a rule.
	##
	## id: The rule to remove, specified as the ID returned by :bro:id:`add_rule` .
	##
	## Returns: True if succesful, the relevant plugin indicated that ity knew how
	## to handle the removal. Note that again "success" means the plugin accepted the
	## removal. They might still fail to put it into effect, as that  might happen
	## asynchronously and thus go wrong at that point.
	global remove_rule: function(id: string) : bool;

	###### Asynchronous feedback on rules.

	## Confirms that a rule was put in place.
	##
	## r: The rule now in place.
	##
	## plugin: The name of the plugin that put it into place.
	##
	## msg: An optional informational message by the plugin.
	global rule_added: event(r: Rule, p: PluginState, msg: string &default="");

	## Reports that a rule was removed due to a remove: function() call.
	##
	## r: The rule now removed.
	##
	## plugin: The name of the plugin that had the rule in place and now
	## removed it.
	##
	## msg: An optional informational message by the plugin.
	global rule_removed: event(r: Rule, p: PluginState, msg: string &default="");

	## Reports that a rule was removed internally due to a timeout.
	##
	## r: The rule now removed.
	##
	## plugin: The name of the plugin that had the rule in place and now
	## removed it.
	##
	## msg: An optional informational message by the plugin.
	global rule_timeout: event(r: Rule, p: PluginState);

	## Reports an error when operating on a rule.
	##
	## r: The rule that encountered an error.
	##
	## plugin: The name of the plugin that reported the error.
	##
	## msg: An optional informational message by the plugin.
	global rule_error: event(r: Rule, p: PluginState, msg: string &default="");

	## Installs a notification.
	##
	## n: The notification to install.
	##
	## Returns: If succesful, returns an ID string unique to the notification that can later
	## be used to refer to it. If unsuccessful, returns an empty string. The ID is also
	## assigned to ``r$id``. Note that "successful" means "a plugin knew how to handle
	## the notification", it doesn't necessarily mean that it was indeed successfully put in
	## place, because that might happen asynchronously and thus fail only later.
	global add_notification: function(n: Notification) : string;

	## Removes a notification.
	##
	## id: The notification to remove, specified as the ID returned by :bro:id:`add_notification` .
	##
	## Returns: True if succesful, the relevant plugin indicated that ity knew how
	## to handle the removal. Note that again "success" means the plugin accepted the
	## removal. They might still fail to put it into effect, as that  might happen
	## asynchronously and thus go wrong at that point.
	global remove_notification: function(id: string) : bool;

	###### Asynchronous feedback on notifications.

	## Confirms that a notification was put in place.
	##
	## n: The notification now in place.
	##
	## plugin: The name of the plugin that put it into place.
	##
	## msg: An optional informational message by the plugin.
	global notification_added: event(n: Notification, p: PluginState, msg: string &default="");

	## Reports that a notification was removed due to a remove: function() call.
	##
	## n: The notification now removed.
	##
	## plugin: The name of the plugin that had the notification in place and now
	## removed it.
	##
	## msg: An optional informational message by the plugin.
	global notification_removed: event(n: Notification, p: PluginState, msg: string &default="");

	## Reports that a notification was removed internally due to a timeout.
	##
	## n: The notification now removed.
	##
	## plugin: The name of the plugin that had the notification in place and now
	## removed it.
	##
	## msg: An optional informational message by the plugin.
	global notification_timeout: event(n: Notification, p: PluginState);

	## Reports an error when operating on a notification.
	##
	## n: The notification that encountered an error.
	##
	## plugin: The name of the plugin that reported the error.
	##
	## msg: An optional informational message by the plugin.
	global notification_error: event(n: Notification, p: PluginState, msg: string &default="");

	## Type of an entry in the PACF log.
	type InfoCategory: enum {
		## A log entry reflecting a framework message.
		MESSAGE,
		## A log entry reflecting a framework message.
		ERROR,
		## A log entry about about a rule.
		RULE,
		## A log entry about about a notification.
		NOTIFICATION
	};

	## State of an  entry in the PACF log.
	type InfoState: enum {
		REQUESTED,
		SUCCEEDED,
		FAILED,
		REMOVED,
		TIMEOUT,
	};

	## The record type which contains column fields of the PACF log.
	type Info: record {
		## Time at which the recorded activity occurred.
		ts: time		&log;
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
		## String with an additional message.
		msg: string		&log &optional;
		## Logcation where the underlying action was triggered.
		location: string	&log &optional;
		## Plugin triggering the log entry.
		plugin: string		&log &optional;
	};
}

redef record Rule += {
	##< Internally set to the plugin handling the rule.
	_plugin: PluginState &optional;
};

global plugins: vector of PluginState;
global rule_counter: count = 0;
global rules: table[string] of Rule;

event bro_init() &priority=5
	{
	Log::create_stream(Pacf::LOG, [$columns=Info]);
	}

function entity_to_info(info: Info, e: Entity)
	{
	info$entity_type = fmt("%s", e$ty);

	switch ( e$ty ) {
		case ADDRESS, ORIGINATOR, RESPONDER:
			info$entity = fmt("%s", e$ip);
			break;

		case CONNECTION:
			info$entity = fmt("%s/%d<->%s/%d",
					  e$conn$orig_h, e$conn$orig_p,
					  e$conn$resp_h, e$conn$resp_p);
			break;

		case FLOW:
			info$entity = fmt("%s/%d->%s/%d",
					  e$flow$src_h, e$flow$src_p,
					  e$flow$dst_h, e$flow$dst_p);
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

	if ( r?$location )
		info$location = r$location;
	
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

function log_rule(r: Rule, cmd: string, state: InfoState, p: PluginState)
	{
	local info: Info = [$ts=network_time()];
	info$category = RULE;
	info$cmd = cmd;
	info$state = state;
	info$plugin = p$plugin$name(p);

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

function activate(p: PluginState, priority: int)
	{
	p$_priority = priority;
	plugins[|plugins|] = p;
	sort(plugins, function(p1: PluginState, p2: PluginState) : int { return p2$_priority - p1$_priority; });

	log_msg(fmt("activated plugin with priority %d", priority), p);
	}

function drop_address(a: addr, t: interval, location: string &default="") : bool
	{
	local e: Entity = [$ty=ADDRESS, $ip=addr_to_subnet(a)];
	local r: Rule = [$ty=DROP, $target=FORWARD, $entity=e, $expire=t, $location=location];
	
	local id = add_rule(r);
	return |id| > 0;
	}

function shunt_flow(f: flow_id, t: interval, location: string &default="") : bool
	{
	local e: Entity = [$ty=FLOW, $flow=f];
	local r: Rule = [$ty=DROP, $target=MONITOR, $entity=e, $expire=t, $location=location];
	
	local id = add_rule(r);
	return |id| > 0;
	}

function reset(e: Entity)
	{
	print "Pacf::reset not implemented yet";
	}

function clear()
	{
	print "Pacf::clear not implemented yet";
	}

function add_rule(r: Rule) : string
	{
	r$id = fmt("%d", ++rule_counter);

	for ( i in plugins )
		{
		local p = plugins[i];

		if ( p$plugin$add_rule(p, r) ) 
			{
			r$_plugin = p;
			log_rule(r, "ADD", REQUESTED, p);
			return r$id;
			}
		}

	log_rule_no_plugin(r, FAILED, "not supported");
	}

function remove_rule(id: string) : bool
	{
	local r = rules[id];
	local p = r$_plugin;
	
	if ( ! p$plugin$remove_rule(r$_plugin, r) ) 
		{
		log_rule_error(r, "remove failed", p);
		return F;
		}

	log_rule(r, "REMOVE", REQUESTED, p);
	return T;
	}

event rule_expire(r: Rule, p: PluginState)
	{
	if ( r$id !in rules )
		# Remove already.
		return;

	event rule_timeout(r, p);
	remove_rule(r$id);
	}

event rule_added(r: Rule, p: PluginState, msg: string &default="")
	{
	log_rule(r, "ADD", SUCCEEDED, p);

	rules[r$id] = r;
	
	if ( r?$expire && ! p$plugin$can_expire )
		schedule r$expire { rule_expire(r, p) };
	}

event rule_removed(r: Rule, p: PluginState, msg: string &default="")
	{
	delete rules[r$id];
	log_rule(r, "REMOVE", SUCCEEDED, p);
	}

event rule_timeout(r: Rule, p: PluginState)
	{
	delete rules[r$id];
	log_rule(r, "EXPIRE", TIMEOUT, p);
	}

event rule_error(r: Rule, p: PluginState, msg: string &default="")
	{
	log_rule_error(r, msg, p);
	}

function add_notification(n: Notification) : string
	{
	print "Pacf::add_notification not implemented yet";
	}

function remove_notification(id: string) : bool
	{
	print "Pacf::remove_notification not implemented yet";
	}

event notification_added(n: Notification, p: PluginState, msg: string &default="")
	{
	}

event notification_removed(n: Notification, p: PluginState, msg: string &default="")
	{
	}

event notification_timeout(n: Notification, p: PluginState)
	{
	}

event notification_error(n: Notification, p: PluginState, msg: string &default="")
	{
	}


