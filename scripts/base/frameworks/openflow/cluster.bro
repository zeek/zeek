@load ./main
@load base/frameworks/cluster

module OpenFlow;

export {
	## This is the event used to transport flow_mod messages to the manager.
	global cluster_flow_mod: event(name: string, match: ofp_match, flow_mod: ofp_flow_mod);

	## This is the event used to transport flow_clear messages to the manager.
	global cluster_flow_clear: event(name: string);
}

## Workers need ability to forward commands to manager.
redef Cluster::worker2manager_events += /OpenFlow::cluster_flow_(mod|clear)/;

global name_to_controller: table[string] of Controller;

# the flow_mod function wrapper
function flow_mod(controller: Controller, match: ofp_match, flow_mod: ofp_flow_mod): bool
	{
	if ( ! controller?$flow_mod )
		return F;

	if ( Cluster::local_node_type() == Cluster::MANAGER )
		return controller$flow_mod(controller$state, match, flow_mod);
	else
		event OpenFlow::cluster_flow_mod(controller$state$_name, match, flow_mod);

	return T;
	}

function flow_clear(controller: Controller): bool
	{
	if ( ! controller?$flow_clear )
		return F;

	if ( Cluster::local_node_type() == Cluster::MANAGER )
		return controller$flow_clear(controller$state);
	else
		event OpenFlow::cluster_flow_clear(controller$state$_name);

	return T;
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event OpenFlow::cluster_flow_mod(name: string, match: ofp_match, flow_mod: ofp_flow_mod)
	{
	if ( name !in name_to_controller )
		{
		Reporter::error(fmt("OpenFlow controller %s not found in mapping on master", name));
		return;
		}

	local c = name_to_controller[name];
	if ( c?$flow_mod )
		c$flow_mod(c$state, match, flow_mod);
	}

event OpenFlow::cluster_flow_clear(name: string)
	{
	if ( name !in name_to_controller )
		{
		Reporter::error(fmt("OpenFlow controller %s not found in mapping on master", name));
		return;
		}

	local c = name_to_controller[name];

	if ( c?$flow_clear )
		c$flow_clear(c$state);
	}
@endif

function register_controller(tpe: OpenFlow::Plugin, name: string, controller: Controller)
	{
	controller$state$_name = cat(tpe, name);
	controller$state$_plugin = tpe;

	# we only run the init functions on the manager.
	if ( Cluster::local_node_type() != Cluster::MANAGER )
		return;

	if ( controller$state$_name in name_to_controller )
		{
		Reporter::error("OpenFlow Controller %s was already registered. Ignored duplicate registration");
		return;
		}

	name_to_controller[controller$state$_name] = controller;

	if ( controller?$init )
		controller$init(controller$state);
	}
