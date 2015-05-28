@load ./main
@load base/frameworks/cluster

module Pacf;

export {
	## This is the event used to transport add_rule calls to the manager.
	global cluster_pacf_add_rule: event(r: Rule);

	## This is the event used to transport remove_rule calls to the manager.
	global cluster_pacf_remove_rule: event(id: string);
}

## Workers need ability to forward commands to manager.
redef Cluster::worker2manager_events += /Pacf::cluster_pacf_(add|remove)_rule/;
## Workers need to see the result events from the manager.
redef Cluster::manager2worker_events += /Pacf::rule_(added|removed|timeout|error)/;


function activate(p: PluginState, priority: int)
	{
	# we only run the activate function on the manager.
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
		if ( r$id == "" )
			r$id = cat(Cluster::node, ":", ++local_rule_count);

		event Pacf::cluster_pacf_add_rule(r);
		return r$id;
		}
	}

function remove_rule(id: string) : bool
	{
	if ( Cluster::local_node_type() == Cluster::MANAGER )
		return remove_rule_impl(id);
	else
		{
		event Pacf::cluster_pacf_remove_rule(id);
		return T; # well, we can't know here. So - just hope...
		}
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event Pacf::cluster_pacf_add_rule(r: Rule)
	{
	add_rule_impl(r);
	}

event Pacf::cluster_pacf_remove_rule(id: string)
	{
	remove_rule_impl(id);
	}
@endif
