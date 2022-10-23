##! Management framework configuration settings common to agent and controller.
##! This does not include config settings that exist in both agent and
##! controller but that they set differently, since setting defaults here would
##! be awkward or pointless (since both node types would overwrite them
##! anyway). For role-specific settings, see management/controller/config.zeek
##! and management/agent/config.zeek.

@load base/misc/installation

@load ./types

module Management;

export {
	## The role of this process in cluster management. Use this to
	## differentiate code based on the type of node in which it ends up
	## running.
	const role = Management::NONE &redef;

	## The fallback listen address if more specific addresses, such as
	## the controller's :zeek:see:`Management::Controller::listen_address`
	## remains empty. Unless redefined, this listens on all interfaces.
	const default_address = "0.0.0.0" &redef;

	## The retry interval for Broker connects. Defaults to a more
	## aggressive value compared to Broker's 30s.
	const connect_retry = 1sec &redef;

	## The toplevel directory in which the Management framework creates
	## spool state for any Zeek nodes, including the Zeek cluster, agents,
	## and the controller. Don't use this directly, use the
	## :zeek:see:`Management::get_spool_dir` function.
	const spool_dir = getenv("ZEEK_MANAGEMENT_SPOOL_DIR") &redef;

	## The toplevel directory for variable state, such as Broker data
	## stores. Don't use this directly, use the
	## :zeek:see:`Management::get_state_dir` function.
	const state_dir = getenv("ZEEK_MANAGEMENT_STATE_DIR") &redef;

	## Returns the effective spool directory for the management framework.
	## That's :zeek:see:`Management::spool_dir` when set, otherwise the
	## installation's spool directory.
	global get_spool_dir: function(): string;

	## Returns the effective state directory for the management framework.
	## That's :zeek:see:`Management::state_dir` when set, otherwise the
	## installation's state directory.
	global get_state_dir: function(): string;
}

function get_spool_dir(): string
	{
	if ( spool_dir != "" )
		return spool_dir;

	return Installation::spool_dir;
	}

function get_state_dir(): string
	{
	if ( state_dir != "" )
		return state_dir;

	return Installation::state_dir;
	}
