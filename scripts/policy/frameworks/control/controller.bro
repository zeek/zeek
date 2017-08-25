##! This is a utility script that implements the controller interface for the
##! control framework.  It's intended to be run to control a remote Bro
##! and then shutdown.
##!
##! It's intended to be used from the command line like this::
##!
##!     bro <scripts> frameworks/control/controller Control::host=<host_addr> Control::host_port=<host_port> Control::cmd=<command> [Control::arg=<arg>]

@load base/frameworks/control
@load base/frameworks/communication
@load base/frameworks/broker

module Control;

# Do some sanity checking and rework the communication nodes.
event bro_init() &priority=5
	{
	# We know that some command was given because this script wouldn't be
	# loaded if there wasn't so we can feel free to throw an error here and
	# shutdown.
	if ( cmd !in commands )
		Reporter::fatal(fmt("The '%s' control command is unknown.", cmd));

	if ( use_broker )
		{
		Broker::auto_publish("bro/event/framework/control/id_value_request",
		                     Control::id_value_request);
		Broker::auto_publish("bro/event/framework/control/peer_status_request",
		                     Control::peer_status_request);
		Broker::auto_publish("bro/event/framework/control/net_stats_request",
		                     Control::net_stats_request);
		Broker::auto_publish("bro/event/framework/control/configuration_update_request",
		                     Control::configuration_update_request);
		Broker::auto_publish("bro/event/framework/control/shutdown_request",
                             Control::shutdown_request);
		Broker::auto_publish("bro/event/framework/control/global_id_update_request",
                             Control::global_id_update_request);
		Broker::subscribe("bro/event/framework/control");
		Broker::peer(cat(host), host_port);
		}
	else
		{
		# Establish the communication configuration and only request response
		# messages.
		Communication::nodes["control"] = [$host=host, $zone_id=zone_id,
		                                   $p=host_port, $sync=F, $connect=T,
		                                   $class="control",
		                                   $events=Control::controllee_events];
		}
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

function configurable_ids(): id_table
	{
	local rval: id_table = table();
	local globals = global_ids();

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
			rval[id] = t;
		}

	return rval;
	}

function send_control_request()
	{
	switch ( cmd ) {
	case "id_value":
		if ( arg == "" )
			Reporter::fatal("The Control::id_value command requires that Control::arg also has some value.");

		event Control::id_value_request(arg);
		break;

	case "peer_status":
		event Control::peer_status_request();
		break;

	case "net_stats":
		event Control::net_stats_request();
		break;

	case "shutdown":
		event Control::shutdown_request();
		break;

	case "configuration_update":
		event Control::configuration_update_request();
		break;

	default:
		Reporter::fatal(fmt("unhandled Control::cmd, %s", cmd));
		break;
	}
	}

event remote_connection_handshake_done(p: event_peer) &priority=-10
	{
	if ( cmd == "configuration_update" )
		{
		# Send all &redef'able consts to the peer.
		local ids = configurable_ids();

		for ( id in ids )
			send_id(p, id);

		Reporter::info(fmt("Control framework sent %d IDs", |ids|));
		}

	send_control_request();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string) &priority=-10
	{
	if ( cmd == "configuration_update" )
		{
		# Send all &redef'able consts to the peer.
		local ids = configurable_ids();
		event Control::global_id_update_request(serialize(ids));
		Reporter::info(fmt("Control framework sent %d IDs", |ids|));
		}

	send_control_request();
	}
