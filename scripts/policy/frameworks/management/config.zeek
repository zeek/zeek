##! Management framework configuration settings common to agent and controller.
##! This does not include config settings that exist in both agent and
##! controller but that they set differently, since setting defaults here would
##! be awkward or pointless (since both node types would overwrite them
##! anyway). For role-specific settings, see management/controller/config.zeek
##! and management/agent/config.zeek.

module Management;

export {
	## The fallback listen address if more specific adddresses, such as
	## the controller's :zeek:see:`Management::Controller::listen_address`
	## remains empty. Unless redefined, this uses Broker's own default
	## listen address.
	const default_address = Broker::default_listen_address &redef;

	## The retry interval for Broker connnects. Defaults to a more
	## aggressive value compared to Broker's 30s.
	const connect_retry = 1sec &redef;
}
