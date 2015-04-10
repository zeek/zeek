##! Bro's openflow control framework
##!
##! This plugin-based framework allows to control Openflow capable
##! switches by implementing communication to an Openflow controller
##! via plugins. The framework has to be instantiated via the new function
##! in one of the plugins. This framework only offers very low-level
##! functionality; if you want to use OpenFlow capable switches, e.g.,
##! for shunting, please look at the PACF framework, which provides higher
##! level functions and can use the OpenFlow framework as a backend.

module OpenFlow;

@load ./consts
@load ./types

export {
	## Global flow_mod function.
	##
	## controller: The controller which should execute the flow modification
	##
	## match: The ofp_match record which describes the flow to match.
	##
	## flow_mod: The openflow flow_mod record which describes the action to take.
	##
	## Returns: F on error or if the plugin does not support the operation, T when the operation was queued.
	global flow_mod: function(controller: Controller, match: ofp_match, flow_mod: ofp_flow_mod): bool;

	## Clear the current flow table of the controller.
	##
	## controller: The controller which should execute the flow modification
	##
	## Returns: F on error or if the plugin does not support the operation, T when the operation was queued.
	global flow_clear: function(controller: Controller): bool;

	## Event confirming successful modification of a flow rule.
	##
	## match: The ofp_match record which describes the flow to match.
	##
	## flow_mod: The openflow flow_mod record which describes the action to take.
	##
	## msg: An optional informational message by the plugin..
	global flow_mod_success: event(match: ofp_match, flow_mod: ofp_flow_mod, msg: string &default="");

	## Reports an error while installing a flow Rule.
	##
	## match: The ofp_match record which describes the flow to match.
	##
	## flow_mod: The openflow flow_mod record which describes the action to take.
	##
	## msg: Message to describe the event.
	global flow_mod_failure: event(match: ofp_match, flow_mod: ofp_flow_mod, msg: string &default="");

	## Convert a conn_id record into an ofp_match record that can be used to
	## create match objects for OpenFlow.
	##
	## id: the conn_id record that describes the record.
	##
	## reverse: reverse the sources and destinations when creating the match record (default F)
	##
	## Returns: ofp_match object for the conn_id record.
	global match_conn: function(id: conn_id, reverse: bool &default=F): ofp_match;

	# ###
	# ### Low-level functions for cookie handling.
	# ###

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
}


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

function match_conn(id: conn_id, reverse: bool &default=F): ofp_match
	{
	local dl_type = ETH_IPv4;
	local proto = IP_TCP;

	local orig_h: addr;
	local orig_p: port;
	local resp_h: addr;
	local resp_p: port;

	if ( reverse == F )
		{
		orig_h = id$orig_h;
		orig_p = id$orig_p;
		resp_h = id$resp_h;
		resp_p = id$resp_p;
		}
	else
		{
		orig_h = id$resp_h;
		orig_p = id$resp_p;
		resp_h = id$orig_h;
		resp_p = id$resp_p;
		}

		if ( is_v6_addr(orig_h) )
			dl_type = ETH_IPv6;

		if ( is_udp_port(orig_p) )
			proto = IP_UDP;
		else if ( is_icmp_port(orig_p) )
			proto = IP_ICMP;

		return ofp_match(
			$dl_type=dl_type,
			$nw_proto=proto,
			$nw_src=orig_h,
			$tp_src=orig_p,
			$nw_dst=resp_h,
			$tp_dst=resp_p
		);
	}

# local function to forge a flow_mod cookie for this framework.
# all flow entries from the openflow framework should have the
# 42 bit of the cookie set.
function generate_cookie(cookie: count &default=0): count
	{
	local c = BRO_COOKIE_ID * COOKIE_BID_START;

	if ( cookie >= COOKIE_UID_SIZE )
		Reporter::warning(fmt("The given cookie uid '%d' is > 32bit and will be discarded", cookie));
	else
		c += cookie;

	return c;
	}

# local function to check if a given flow_mod cookie is forged from this framework.
function is_valid_cookie(cookie: count): bool
	{
	if ( cookie / COOKIE_BID_START == BRO_COOKIE_ID )
		return T;

	Reporter::warning(fmt("The given Openflow cookie '%d' is not valid", cookie));

	return F;
	}

function get_cookie_uid(cookie: count): count
	{
	if( is_valid_cookie(cookie) )
		return (cookie - ((cookie / COOKIE_GID_START) * COOKIE_GID_START));

	return INVALID_COOKIE;
	}

function get_cookie_gid(cookie: count): count
	{
	if( is_valid_cookie(cookie) )
		return (
			(cookie	- (COOKIE_BID_START * BRO_COOKIE_ID) -
			(cookie - ((cookie / COOKIE_GID_START) * COOKIE_GID_START))) /
			COOKIE_GID_START
		);

	return INVALID_COOKIE;
	}
