##! This is a utility script that sends the current values of all &redef'able 
##! consts to a remote Bro then sends the :bro:id:`configuration_update` event
##! and terminates processing.
##!
##! Intended to be used from the command line like this when starting a controller:
##!     bro <scripts> frameworks/control/controller Control::host=<host_addr> Control::port=<host_port> Control::cmd=<command> [Control::arg=<arg>]
##!
##! To use the framework as a controllee, it only needs to be loaded and
##! the controlled node need to accept all events in the "Control::" namespace
##! from the host where the control actions will be performed from along with
##! using the "control" class.

module Control;

export {
	## This is the address of the host that will be controlled.
	const host = 0.0.0.0 &redef;
	
	## This is the port of the host that will be controlled.
	const host_port = 0/tcp &redef;

	## This is the command that is being done.  It's typically set on the 
	## command line and influences whether this instance starts up as a
	## controller or controllee.  If left blank this node will start as a 
	## controllee and a controller if there is a given command.
	const cmd = "" &redef;
	
	## This can be used by commands that take an argument.
	const arg = "" &redef;
	
	const controller_events = /Control::.*_request/ &redef;
	const controllee_events = /Control::.*_response/ &redef;

	## These are the commands that can be given on the command line for
	## remote control.
	const commands: set[string] = { 
		"id_value",
		"peer_status",
		"net_stats",
		"configuration_update",
		"shutdown",
	};
	
	## Variable IDs that are to be ignored by the update process.
	const ignore_ids: set[string] = {
		# FIXME: Bro crashes if it tries to send this ID.
		"Log::rotation_control",
	};
	
	## Event for requesting the value of an ID (a variable).
	global id_value_request: event(id: string);
	## Event for returning the value of an ID after an :bro:id:`id_request` event.
	global id_value_response: event(id: string, val: string);
	
	## Requests the current communication status.
	global peer_status_request: event();
	## Returns the current communication status.
	global peer_status_response: event(s: string);
	
	## Requests the current net_stats.
	global net_stats_request: event();
	## Returns the current net_stats.
	global net_stats_response: event(s: string);
	
	## Inform the remote Bro instance that it's configuration may have been updated.
	global configuration_update_request: event();
	## This event is a wrapper and alias for the :bro:id:`configuration_update_request` event.
	## This event is also a primary hooking point for the control framework.
	global configuration_update: event();
	## Message in response to a configuration update request.
	global configuration_update_response: event();
	
	## Requests that the Bro instance begins shutting down.
	global shutdown_request: event();
	## Message in response to a shutdown request.
	global shutdown_response: event();
}


event terminate_event()
	{
	terminate_communiction();
	}
