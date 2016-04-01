##! The control framework provides the foundation for providing "commands"
##! that can be taken remotely at runtime to modify a running Bro instance
##! or collect information from the running instance.

module Control;

export {
	## The address of the host that will be controlled.
	const host = 0.0.0.0 &redef;

	## The port of the host that will be controlled.
	const host_port = 0/tcp &redef;

	## If :bro:id:`Control::host` is a non-global IPv6 address and
	## requires a specific :rfc:`4007` ``zone_id``, it can be set here.
	const zone_id = "" &redef;

	## The command that is being done.  It's typically set on the
	## command line.
	const cmd = "" &redef;

	## This can be used by commands that take an argument.
	const arg = "" &redef;

	## Events that need to be handled by controllers.
	const controller_events : set[string] = {"Control::id_value_request", "Control::peer_status_request", "Control::net_stats_request", "Control::shutdown_request"} &redef;
	
	## Events that need to be handled by controllees.
	const controllee_events : set[string] = {"Control::id_value_response", "Control::peer_status_response", "Control::net_stats_response", "Control::shutdown_response"} &redef;

	## The commands that can currently be given on the command line for
	## remote control.
	const commands: set[string] = {
		"id_value",
		"peer_status",
		"net_stats",
		"shutdown",
	} &redef;

	## Variable IDs that are to be ignored by the update process.
	const ignore_ids: set[string] = { };

	## Event for requesting the value of an ID (a variable).
	global id_value_request: event(id: string);
	## Event for returning the value of an ID after an
	## :bro:id:`Control::id_value_request` event.
	global id_value_response: event(id: string, val: string);

	## Requests the current communication status.
	global peer_status_request: event();
	## Returns the current communication status.
	global peer_status_response: event(s: string);

	## Requests the current net_stats.
	global net_stats_request: event();
	## Returns the current net_stats.
	global net_stats_response: event(s: string);

	## Requests that the Bro instance begins shutting down.
	global shutdown_request: event();
	## Message in response to a shutdown request.
	global shutdown_response: event();

	# Pub-sub prefix for broker communication
	const pub_sub_prefix : string = "bro/event/control/" &redef;
}


event terminate_event()
	{
	terminate();
	}
