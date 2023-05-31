##! Cluster support for the OpenFlow framework.

@load ./main
@load base/frameworks/cluster

module OpenFlow;

export {
	## This is the event used to transport flow_mod messages to the manager.
	global cluster_flow_mod: event(name: string, match: ofp_match, flow_mod: ofp_flow_mod);

	## This is the event used to transport flow_clear messages to the manager.
	global cluster_flow_clear: event(name: string);
}

@if ( Cluster::local_node_type() != Cluster::MANAGER )
# Workers need ability to forward commands to manager.
event zeek_init()
	{
	Broker::auto_publish(Cluster::manager_topic, OpenFlow::cluster_flow_mod);
	Broker::auto_publish(Cluster::manager_topic, OpenFlow::cluster_flow_clear);
	}
@endif

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

	if ( ! c$state$_activated )
		return;

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

	if ( ! c$state$_activated )
		return;

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

	register_controller_impl(tpe, name, controller);
	}

function unregister_controller(controller: Controller)
	{
	# we only run the on the manager.
	if ( Cluster::local_node_type() != Cluster::MANAGER )
		return;

	unregister_controller_impl(controller);
	}

function lookup_controller(name: string): vector of Controller
	{
	# we only run the on the manager. Otherwise we don't have a mapping or state -> return empty
	if ( Cluster::local_node_type() != Cluster::MANAGER )
		return vector();

	# I am not quite sure if we can actually get away with this - in the
	# current state, this means that the individual nodes cannot lookup
	# a controller by name.
	#
	# This means that there can be no reactions to things on the actual
	# worker nodes - because they cannot look up a name. On the other hand -
	# currently we also do not even send the events to the worker nodes (at least
	# not if we are using broker). Because of that I am not really feeling that
	# badly about it...

	return lookup_controller_impl(name);
	}
