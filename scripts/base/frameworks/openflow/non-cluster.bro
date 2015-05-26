@load ./main

module OpenFlow;

# the flow_mod function wrapper
function flow_mod(controller: Controller, match: ofp_match, flow_mod: ofp_flow_mod): bool
	{
	if ( controller?$flow_mod )
		return controller$flow_mod(controller$state, match, flow_mod);
	else
		return F;
	}

function flow_clear(controller: Controller): bool
	{
	if ( controller?$flow_clear )
		return controller$flow_clear(controller$state);
	else
		return F;
	}

function register_controller(tpe: OpenFlow::Plugin, name: string, controller: Controller)
	{
	controller$state$_name = cat(tpe, name);
	controller$state$_plugin = tpe;

	if ( controller?$init )
		controller$init(controller$state);
	}
