@load ./main

module OpenFlow;

# the flow_mod function wrapper
function flow_mod(controller: Controller, match: ofp_match, flow_mod: ofp_flow_mod): bool
	{
	if ( ! controller$state$_activated )
		return F;

	if ( controller?$flow_mod )
		return controller$flow_mod(controller$state, match, flow_mod);
	else
		return F;
	}

function flow_clear(controller: Controller): bool
	{
	if ( ! controller$state$_activated )
		return F;

	if ( controller?$flow_clear )
		return controller$flow_clear(controller$state);
	else
		return F;
	}

function register_controller(tpe: OpenFlow::Plugin, name: string, controller: Controller)
	{
	controller$state$_name = cat(tpe, name);
	controller$state$_plugin = tpe;

	register_controller_impl(tpe, name, controller);
	}

function unregister_controller(controller: Controller)
	{
	unregister_controller_impl(controller);
	}

function lookup_controller(name: string): vector of Controller
	{
	return lookup_controller_impl(name);
	}
