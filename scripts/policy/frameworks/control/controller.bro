##! This is a utility script that implements the controller interface for the
##! control framework.  It's intended to be run to control a remote Bro
##! and then shutdown.
##!
##! It's intended to be used from the command line like this::
##!
##!     bro <scripts> frameworks/control/controller Control::host=<host_addr> Control::port=<host_port> Control::cmd=<command> [Control::arg=<arg>]

@load base/frameworks/control
@load base/frameworks/communication

module Control;

# Do some sanity checking and rework the communication nodes.
event bro_init() &priority=5
	{
	# We know that some command was given because this script wouldn't be
	# loaded if there wasn't so we can feel free to throw an error here and
	# shutdown.
	if ( cmd !in commands )
		{
		# TODO: do an actual error here.  Maybe through the reporter events?
		print fmt("The '%s' control command is unknown.", cmd);
		terminate();
		}
	
	# Establish the communication configuration and only request response
	# messages.
	Communication::nodes["control"] = [$host=host, $zone_id=zone_id,
	                                   $p=host_port, $sync=F, $connect=T,
	                                   $class="control", $events=Control::controllee_events];
	}


event Control::id_value_response(id: string, val: string) &priority=-10
	{
	event terminate_event();
	}

event Control::peer_status_response(s: string) &priority=-10
	{
	event terminate_event();
	}

event Control::net_stats_response(s: string) &priority=-10
	{
	event terminate_event();
	}
	
event Control::configuration_update_response() &priority=-10
	{
	event terminate_event();
	}

event Control::shutdown_response() &priority=-10
	{
	event terminate_event();
	}
	
function configuration_update_func(p: event_peer)
	{
	# Send all &redef'able consts to the peer.
	local globals = global_ids();
    local cnt = 0;
	for ( id in globals )
		{
        if ( id in ignore_ids )
			next;

		local t = globals[id];

		# Skip it if the variable isn't redefinable or not const.
		# We don't want to update non-const globals because that's usually
		# where state is stored and those values will frequently be declared
		# with &redef so that attributes can be redefined.
		# 
		# NOTE: functions are currently not fully supported for serialization and hence
		# aren't sent.
		if ( t$constant && t$redefinable && t$type_name != "func" )
			{
			send_id(p, id);
			++cnt;
			}
		}

	print fmt("sent %d IDs", cnt);
	event terminate_event();
	}

event remote_connection_handshake_done(p: event_peer) &priority=-10
	{
	if ( cmd == "id_value" )
		{
		if ( arg != "" )
			event Control::id_value_request(arg);
		else
			{
			# TODO: do an actual error here.  Maybe through the reporter events?
			print "The id_value command requires that Control::arg have some value.";
			terminate();
			}
		}
	else if ( cmd == "peer_status" )
		event Control::peer_status_request();
	else if ( cmd == "net_stats" )
		event Control::net_stats_request();
	else if ( cmd == "shutdown" )
		event Control::shutdown_request();
	else if ( cmd == "configuration_update" )
		{
		configuration_update_func(p);
		# Signal configuration update to peer.
		event Control::configuration_update_request();
		}
	}
