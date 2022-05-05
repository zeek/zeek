##! The control framework provides the foundation for providing "commands"
##! that can be taken remotely at runtime to modify a running Zeek instance
##! or collect information from the running instance.

module Control;

export {
	## The topic prefix used for exchanging control messages via Broker.
	const topic_prefix = "zeek/control";

	## Whether the controllee should call :zeek:see:`Broker::listen`.
	## In a cluster, this isn't needed since the setup process calls it.
	const controllee_listen = T &redef;

	## The address of the host that will be controlled.
	const host = 0.0.0.0 &redef;

	## The port of the host that will be controlled.
	const host_port = 0/tcp &redef;

	## If :zeek:id:`Control::host` is a non-global IPv6 address and
	## requires a specific :rfc:`4007` ``zone_id``, it can be set here.
	const zone_id = "" &redef;

	## The command that is being done.  It's typically set on the
	## command line.
	const cmd = "" &redef;

	## This can be used by commands that take an argument.
	const arg = "" &redef;

	## The commands that can currently be given on the command line for
	## remote control.
	const commands: set[string] = {
		"id_value",
		"peer_status",
		"net_stats",
		"configuration_update",
		"shutdown",
	} &redef;

	## Variable IDs that are to be ignored by the update process.
	const ignore_ids: set[string] = { };

	## Event for requesting the value of an ID (a variable).
	global id_value_request: event(id: string);
	## Event for returning the value of an ID after an
	## :zeek:id:`Control::id_value_request` event.
	global id_value_response: event(id: string, val: string);

	## Requests the current communication status.
	global peer_status_request: event();
	## Returns the current communication status.
	global peer_status_response: event(s: string);

	## Requests the current net_stats.
	global net_stats_request: event();
	## Returns the current net_stats.
	global net_stats_response: event(s: string);

	## Inform the remote Zeek instance that it's configuration may have been
	## updated.
	global configuration_update_request: event();
	## This event is a wrapper and alias for the
	## :zeek:id:`Control::configuration_update_request` event.
	## This event is also a primary hooking point for the control framework.
	global configuration_update: event();
	## Message in response to a configuration update request.
	global configuration_update_response: event();

	## Requests that the Zeek instance begins shutting down.
	global shutdown_request: event();
	## Message in response to a shutdown request.
	global shutdown_response: event();
}

event terminate_event() &is_used
	{
	terminate();
	}
