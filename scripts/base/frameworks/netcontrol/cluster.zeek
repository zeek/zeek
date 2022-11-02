##! Cluster support for the NetControl framework.

@load ./main
@load base/frameworks/cluster

module NetControl;

export {
	## This is the event used to transport add_rule calls to the manager.
	global cluster_netcontrol_add_rule: event(r: Rule);

	## This is the event used to transport remove_rule calls to the manager.
	global cluster_netcontrol_remove_rule: event(id: string, reason: string);

	## This is the event used to transport delete_rule calls to the manager.
	global cluster_netcontrol_delete_rule: event(id: string, reason: string);
}

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event zeek_init()
	{
	Broker::auto_publish(Cluster::worker_topic, NetControl::rule_added);
	Broker::auto_publish(Cluster::worker_topic, NetControl::rule_removed);
	Broker::auto_publish(Cluster::worker_topic, NetControl::rule_timeout);
	Broker::auto_publish(Cluster::worker_topic, NetControl::rule_error);
	Broker::auto_publish(Cluster::worker_topic, NetControl::rule_exists);
	Broker::auto_publish(Cluster::worker_topic, NetControl::rule_new);
	Broker::auto_publish(Cluster::worker_topic, NetControl::rule_destroyed);
	}
@else
event zeek_init()
	{
	Broker::auto_publish(Cluster::manager_topic, NetControl::cluster_netcontrol_add_rule);
	Broker::auto_publish(Cluster::manager_topic, NetControl::cluster_netcontrol_remove_rule);
	Broker::auto_publish(Cluster::manager_topic, NetControl::cluster_netcontrol_delete_rule);
	}
@endif

function activate(p: PluginState, priority: int)
	{
	# We only run the activate function on the manager.
	if ( Cluster::local_node_type() != Cluster::MANAGER )
		return;

	activate_impl(p, priority);
	}

global local_rule_count: count = 1;

function add_rule(r: Rule) : string
	{
	if ( Cluster::local_node_type() == Cluster::MANAGER )
		return add_rule_impl(r);
	else
		{
		# We sync rule entities across the cluster, so we
		# actually can test if the rule already exists. If yes,
		# refuse insertion already at the node.

		if ( [r$entity, r$ty] in rule_entities )
			{
			log_rule_no_plugin(r, FAILED, "discarded duplicate insertion");
			return "";
			}

		if ( r$id == "" )
			r$id = cat(Cluster::node, ":", ++local_rule_count);

		event NetControl::cluster_netcontrol_add_rule(r);
		return r$id;
		}
	}

function delete_rule(id: string, reason: string &default="") : bool
	{
	if ( Cluster::local_node_type() == Cluster::MANAGER )
		return delete_rule_impl(id, reason);
	else
		{
		event NetControl::cluster_netcontrol_delete_rule(id, reason);
		return T; # well, we can't know here. So - just hope...
		}
	}

function remove_rule(id: string, reason: string &default="") : bool
	{
	if ( Cluster::local_node_type() == Cluster::MANAGER )
		return remove_rule_impl(id, reason);
	else
		{
		event NetControl::cluster_netcontrol_remove_rule(id, reason);
		return T; # well, we can't know here. So - just hope...
		}
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event NetControl::cluster_netcontrol_delete_rule(id: string, reason: string)
	{
	delete_rule_impl(id, reason);
	}

event NetControl::cluster_netcontrol_add_rule(r: Rule)
	{
	add_rule_impl(r);
	}

event NetControl::cluster_netcontrol_remove_rule(id: string, reason: string)
	{
	remove_rule_impl(id, reason);
	}

event rule_expire(r: Rule, p: PluginState) &priority=-5
	{
	rule_expire_impl(r, p);
	}

event rule_exists(r: Rule, p: PluginState, msg: string) &priority=5
	{
	rule_added_impl(r, p, T, msg);

	if ( r?$expire && r$expire > 0secs && ! p$plugin$can_expire )
		schedule r$expire { rule_expire(r, p) };
	}

event rule_added(r: Rule, p: PluginState, msg: string) &priority=5
	{
	rule_added_impl(r, p, F, msg);

	if ( r?$expire && r$expire > 0secs && ! p$plugin$can_expire )
		schedule r$expire { rule_expire(r, p) };
	}

event rule_removed(r: Rule, p: PluginState, msg: string) &priority=-5
	{
	rule_removed_impl(r, p, msg);
	}

event rule_timeout(r: Rule, i: FlowInfo, p: PluginState) &priority=-5
	{
	rule_timeout_impl(r, i, p);
	}

event rule_error(r: Rule, p: PluginState, msg: string) &priority=-5
	{
	rule_error_impl(r, p, msg);
	}
@endif

# Workers use the events to keep track in their local state tables
@if ( Cluster::local_node_type() != Cluster::MANAGER )

event rule_new(r: Rule) &priority=5
	{
	if ( r$id in rules )
		return;

	rules[r$id] = r;
	rule_entities[r$entity, r$ty] = r;

	add_subnet_entry(r);
	}

event rule_destroyed(r: Rule) &priority=5
	{
	if ( r$id !in rules )
		return;

	remove_subnet_entry(r);
	if ( [r$entity, r$ty] in rule_entities )
		delete rule_entities[r$entity, r$ty];

	delete rules[r$id];
	}

@endif
