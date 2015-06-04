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
	## Returns: The id of the inserted rule on succes and zero on failure.
	global drop_address: function(a: addr, t: interval, location: string &default="") : string;

	## Stops all packets involving an connection address from being forwarded.
	##
	## c: The connection to be dropped.
	##
	## t: How long to drop it, with 0 being indefinitly.
	##
	## location: An optional string describing where the drop was triggered.
	##
	## Returns: The id of the inserted rule on succes and zero on failure.
	global drop_connection: function(c: conn_id, t: interval, location: string &default="") : string;

	## Stops forwarding a uni-directional flow's packets to Bro.
	##
	## f: The flow to shunt.
	##
	## t: How long to leave the shunt in place, with 0 being indefinitly.
	##
	## location: An optional string describing where the shunt was triggered.
	##
	## Returns: The id of the inserted rule on succes and zero on failure.
	global shunt_flow: function(f: flow_id, t: interval, location: string &default="") : string;

	## Allows all traffic involving a specific IP address to be forwarded.
	##
	## a: The address to be whitelistet.
	##
	## t: How long to whitelist it, with 0 being indefinitly.
	##
	## location: An optional string describing whitelist was triddered.
	##
	## Returns: The id of the inserted rule on succes and zero on failure.
	global whitelist_address: function(a: addr, t: interval, location: string &default="") : string;

	## Allows all traffic involving a specific IP subnet to be forwarded.
	##
	## s: The subnet to be whitelistet.
	##
	## t: How long to whitelist it, with 0 being indefinitly.
	##
	## location: An optional string describing whitelist was triddered.
	##
	## Returns: The id of the inserted rule on succes and zero on failure.
	global whitelist_subnet: function(s: subnet, t: interval, location: string &default="") : string;

	## Redirects an uni-directional flow to another port.
	##
	## f: The flow to redirect.
	##
	## out_port: Port to redirect the flow to
	##
	## t: How long to leave the redirect in place, with 0 being indefinitly.
	##
	## location: An optional string describing where the redirect was triggered.
	##
	## Returns: The id of the inserted rule on succes and zero on failure.
	global redirect_flow: function(f: flow_id, out_port: count, t: interval, location: string &default="") : string;

	## Quarantines a host by redirecting rewriting DNS queries to the network dns server dns
	## to the host. Host has to answer to all queries with its own address. Only http communication
	## from infected to quarantinehost is allowed.
	##
	## infected: the host to quarantine
	##
	## dns: the network dns server
	##
	## quarantine: the quarantine server running a dns and a web server
	##
	## t: how long to leave the quarantine in place
	##
	## Returns: Vector of inserted rules on success, empty list on failure.
	global quarantine_host: function(infected: addr, dns: addr, quarantine: addr, t: interval, location: string) : vector of string;

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
	## i: Additional flow information, if supported by the protocol.
	##
	## plugin: The name of the plugin that had the rule in place and now
	## removed it.
	##
	## msg: An optional informational message by the plugin.
	global rule_timeout: event(r: Rule, i: FlowInfo, p: PluginState);

	## Reports an error when operating on a rule.
	##
	## r: The rule that encountered an error.
	##
	## plugin: The name of the plugin that reported the error.
	##
	## msg: An optional informational message by the plugin.
	global rule_error: event(r: Rule, p: PluginState, msg: string &default="");

	## Hook that allows the modification of rules passed to add_rule before they
	## are passed on to the plugins. If one of the hooks uses break, the rule is
	## ignored and not passed on to any plugin.
	##
	## r: The rule to be added
	global Pacf::rule_policy: hook(r: Rule);

	## Type of an entry in the PACF log.
	type InfoCategory: enum {
		## A log entry reflecting a framework message.
		MESSAGE,
		## A log entry reflecting a framework message.
		ERROR,
		## A log entry about about a rule.
		RULE
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

	## Event that can be handled to access the :bro:type:`Pacf::Info`
	## record as it is sent on to the logging framework.
	global log_pacf: event(rec: Info);
}

redef record Rule += {
	##< Internally set to the plugin handling the rule.
	_plugin_id: count &optional;
};

global plugins: vector of PluginState;
global plugin_ids: table[count] of PluginState;
global rule_counter: count = 1;
global plugin_counter: count = 1;
global rules: table[string,count] of Rule; # Rules indexed by id and cid
global id_to_cids: table[string] of set[count]; # id to cid

event bro_init() &priority=5
	{
	Log::create_stream(Pacf::LOG, [$columns=Info, $ev=log_pacf, $path="pacf"]);
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

function drop_connection(c: conn_id, t: interval, location: string &default="") : string
	{
	local e: Entity = [$ty=CONNECTION, $conn=c];
	local r: Rule = [$ty=DROP, $target=FORWARD, $entity=e, $expire=t, $location=location];

	return add_rule(r);
	}

function drop_address(a: addr, t: interval, location: string &default="") : string
	{
	local e: Entity = [$ty=ADDRESS, $ip=addr_to_subnet(a)];
	local r: Rule = [$ty=DROP, $target=FORWARD, $entity=e, $expire=t, $location=location];

	return add_rule(r);
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

function shunt_flow(f: flow_id, t: interval, location: string &default="") : string
	{
	local flow = Pacf::Flow(
		$src_h=addr_to_subnet(f$src_h),
		$src_p=f$src_p,
		$dst_h=addr_to_subnet(f$dst_h),
		$dst_p=f$dst_p
	);
	local e: Entity = [$ty=FLOW, $flow=flow];
	local r: Rule = [$ty=DROP, $target=MONITOR, $entity=e, $expire=t, $location=location];

	return add_rule(r);
	}

function redirect_flow(f: flow_id, out_port: count, t: interval, location: string &default="") : string
	{
	local flow = Pacf::Flow(
		$src_h=addr_to_subnet(f$src_h),
		$src_p=f$src_p,
		$dst_h=addr_to_subnet(f$dst_h),
		$dst_p=f$dst_p
	);
	local e: Entity = [$ty=FLOW, $flow=flow];
	local r: Rule = [$ty=REDIRECT, $target=FORWARD, $entity=e, $expire=t, $location=location, $c=out_port];

	return add_rule(r);
	}

function quarantine_host(infected: addr, dns: addr, quarantine: addr, t: interval, location: string &default="") : vector of string
	{
	local orules: vector of string = vector();
	local edrop: Entity = [$ty=FLOW, $flow=Flow($src_h=addr_to_subnet(infected))];
	local rdrop: Rule = [$ty=DROP, $target=FORWARD, $entity=edrop, $expire=t, $location=location];
	orules[|orules|] = add_rule(rdrop);

	local todnse: Entity = [$ty=FLOW, $flow=Flow($src_h=addr_to_subnet(infected), $dst_h=addr_to_subnet(dns), $dst_p=53/udp)];
	local todnsr = Rule($ty=MODIFY, $target=FORWARD, $entity=todnse, $expire=t, $location=location, $mod=FlowMod($dst_h=quarantine), $priority=+5);
	orules[|orules|] = add_rule(todnsr);

	local fromdnse: Entity = [$ty=FLOW, $flow=Flow($src_h=addr_to_subnet(dns), $src_p=53/udp, $dst_h=addr_to_subnet(infected))];
	local fromdnsr = Rule($ty=MODIFY, $target=FORWARD, $entity=fromdnse, $expire=t, $location=location, $mod=FlowMod($src_h=dns), $priority=+5);
	orules[|orules|] = add_rule(fromdnsr);

	local wle: Entity = [$ty=FLOW, $flow=Flow($src_h=addr_to_subnet(infected), $dst_h=addr_to_subnet(quarantine), $dst_p=80/tcp)];
	local wlr = Rule($ty=WHITELIST, $target=FORWARD, $entity=wle, $expire=t, $location=location, $priority=+5);
	orules[|orules|] = add_rule(wlr);

	return orules;
	}


# Low-level functions that only runs on the manager (or standalone) Bro node.

function activate_impl(p: PluginState, priority: int)
	{
	p$_priority = priority;
	plugins[|plugins|] = p;
	sort(plugins, function(p1: PluginState, p2: PluginState) : int { return p2$_priority - p1$_priority; });

	plugin_ids[plugin_counter] = p;
	p$_id = plugin_counter;
	++plugin_counter;

	# perform one-timi initialization
	if ( p$plugin?$init )
		p$plugin$init(p);

	log_msg(fmt("activated plugin with priority %d", priority), p);
	}

function add_rule_impl(rule: Rule) : string
	{
	rule$cid = ++rule_counter; # numeric id that can be used by plugins for their rules.

	if ( ! rule?$id || rule$id == "" )
		rule$id = cat(rule$cid);

	if ( ! hook Pacf::rule_policy(rule) )
		return "";

	local accepted = F;
	local priority: int = +0;
	local r = rule;

	for ( i in plugins )
		{
		local p = plugins[i];

		# in this case, rule was accepted by earlier plugin and thus plugin has same
		# priority. accept, but give out new rule id.
		if ( accepted == T && p$_priority == priority )
			{
			r = copy(rule);
			r$cid = ++rule_counter;
			}
		else if ( accepted == T )
		# in this case, rule was accepted by earlier plugin and this plugin has a lower
		# priority. Abort and do not send there...
			break;

		# set before, in case the plugins sends and regenerates the plugin record later.
		r$_plugin_id = p$_id;

		if ( p$plugin$add_rule(p, r) )
			{
			accepted = T;
			priority = p$_priority;
			log_rule(r, "ADD", REQUESTED, p);
			}
		}

	if ( accepted )
		return rule$id;

	log_rule_no_plugin(r, FAILED, "not supported");
	return "";
	}

function remove_single_rule(id: string, cid: count) : bool
	{
	if ( [id,cid] !in rules )
		{
		Reporter::error(fmt("Rule %s -- %d does not exist in Pacf::remove_single_rule", id, cid));
		return F;
		}

	local r = rules[id,cid];
	local p = plugin_ids[r$_plugin_id];

	# remove the respective rules from its plugins..
	if ( ! p$plugin$remove_rule(p, r) )
		{
		log_rule_error(r, "remove failed", p);
		return F;
		}

	log_rule(r, "REMOVE", REQUESTED, p);
	return T;
	}

function remove_rule_impl(id: string) : bool
	{
	if ( id !in id_to_cids )
		{
		Reporter::error(fmt("Rule %s does not exist in Pacf::remove_rule", id));
		return F;
		}

	local cids = id_to_cids[id];

	local success = T;
	for ( cid in cids )
		{
		if ( [id,cid] !in rules )
			{
			Reporter::error(fmt("Internal error in pacf::remove_rule - cid %d does not belong to rule %s", cid, id));
			delete cids[cid];
			next;
			}

		if ( ! remove_single_rule(id, cid) )
			success = F;
		}

	return success;
	}

event rule_expire(r: Rule, p: PluginState)
	{
	if ( [r$id,r$cid] !in rules )
		# Removed already.
		return;

	event rule_timeout(r, FlowInfo(), p);
	remove_single_rule(r$id, r$cid);
	}

event rule_added(r: Rule, p: PluginState, msg: string &default="")
	{
	log_rule(r, "ADD", SUCCEEDED, p);

	rules[r$id,r$cid] = r;
	if ( r$id !in id_to_cids )
		id_to_cids[r$id] = set();

	add id_to_cids[r$id][r$cid];

	if ( r?$expire && ! p$plugin$can_expire )
		schedule r$expire { rule_expire(r, p) };
	}

event rule_removed(r: Rule, p: PluginState, msg: string &default="")
	{
	delete rules[r$id,r$cid];
	delete id_to_cids[r$id][r$cid];
	if ( |id_to_cids[r$id]| == 0 )
		delete id_to_cids[r$id];

	log_rule(r, "REMOVE", SUCCEEDED, p);
	}

event rule_timeout(r: Rule, i: FlowInfo, p: PluginState)
	{
	delete rules[r$id,r$cid];
	delete id_to_cids[r$id][r$cid];
	if ( |id_to_cids[r$id]| == 0 )
		delete id_to_cids[r$id];

	log_rule(r, "EXPIRE", TIMEOUT, p);
	}

event rule_error(r: Rule, p: PluginState, msg: string &default="")
	{
	log_rule_error(r, msg, p);
	# errors can occur during deletion. Since this probably means we wo't hear
	# from it again, let's just remove it if it exists...
	delete rules[r$id,r$cid];
	delete id_to_cids[r$id][r$cid];
	if ( |id_to_cids[r$id]| == 0 )
		delete id_to_cids[r$id];
	}

function clear()
	{
	for ( [id,cid] in rules )
		remove_single_rule(id, cid);
	}
