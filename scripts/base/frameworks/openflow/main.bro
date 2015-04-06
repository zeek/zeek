@load ./consts

module Openflow;

export {
	## Function to get the unique id out of a given cookie.
	##
	## cookie: The openflow match cookie.
	##
	## Returns: The cookie unique id.
	global get_cookie_uid: function(cookie: count): count;

	## Function to get the group id out of a given cookie.
	##
	## cookie: The openflow match cookie.
	##
	## Returns: The cookie group id.
	global get_cookie_gid: function(cookie: count): count;

	## Function to generate a new cookie using our group id.
	##
	## cookie: The openflow match cookie.
	##
	## Returns: The cookie group id.
	global generate_cookie: function(cookie: count &default=0): count;

	## Event to signal that a flow has been successfully modified.
	##
	## flow_mod: The openflow flow_mod record which describes
	##           the flow to delete, modify or add.
	##
	## msg: Message to describe the event.
	global Openflow::flow_mod_success: event(flow_mod: ofp_flow_mod, msg: string &default="Flow successfully modified");

	## Event to signal that a flow mod has failed.
	##
	## flow_mod: The openflow flow_mod record which describes
	##           the flow to delete, modify or add.
	##
	## msg: Message to describe the event.
	global Openflow::flow_mod_failure: event(flow_mod: ofp_flow_mod, msg: string &default="Could not modify flow");

	## Available openflow plugins
	type Plugin: enum {
		PLACEHOLDER,
	};

	## Controller related state.
	## Can be redefined by plugins to
	## add state.
	type ControllerState: record {
		## Controller ip.
		host: addr &optional;
		## Controller listen port.
		host_port: count &optional;
		## Openflow switch datapath id.
		dpid: count &optional;
		## Type of the openflow plugin.
		type_: Plugin;
	} &redef;

	## Controller record representing an openflow controller
	type Controller: record {
		## Controller related state.
		state: ControllerState;
		## flow_mod function the plugin implements
		flow_mod: function(state: ControllerState, flow_mod: ofp_flow_mod): bool;
		## flow_stats function the plugin implements if existing 
		## flow_stats: function(state: ControllerState): vector of ofp_flow_stats &optional;
	};

	## Global flow_mod function wrapper
	##
	## controller: The controller which should execute the flow modification
	##
	## flow_mod: The openflow flow_mod record which describes
	##           the flow to delete, modify or add
	##
	## Returns: T if successfull, else F
	global flow_mod: function(controller: Controller, flow_mod: ofp_flow_mod): bool;
}

# the flow_mod function wrapper
function flow_mod(controller: Controller, flow_mod: ofp_flow_mod): bool
	{
		return controller$flow_mod(controller$state, flow_mod);
	}


# local function to forge a flow_mod cookie for this framework.
# all flow entries from the openflow framework should have the
# 42 bit of the cookie set.
function generate_cookie(cookie: count &default=0): count
	{
	local c = BRO_COOKIE_ID * COOKIE_BID_START;
	if(cookie >= COOKIE_UID_SIZE)
		Reporter::warning(fmt("The given cookie uid '%d' is > 32bit and will be discarded", cookie));
	else
		c += cookie;
	return c;
	}


# local function to check if a given flow_mod cookie is forged from this framework.
function _is_valid_cookie(cookie: count): bool
	{
	if (cookie / COOKIE_BID_START == BRO_COOKIE_ID)
		return T;
	Reporter::warning(fmt("The given Openflow cookie '%d' is not valid", cookie));
	return F;
	}


function get_cookie_uid(cookie: count): count
	{
	if(_is_valid_cookie(cookie))
		return (cookie - ((cookie / COOKIE_GID_START) * COOKIE_GID_START));
	return INVALID_COOKIE;
	}


function get_cookie_gid(cookie: count): count
	{
	if(_is_valid_cookie(cookie))
		return (
			(cookie	- (COOKIE_BID_START * BRO_COOKIE_ID) - 
			(cookie - ((cookie / COOKIE_GID_START) * COOKIE_GID_START))) /
			COOKIE_GID_START
		);
	return INVALID_COOKIE;
	}
