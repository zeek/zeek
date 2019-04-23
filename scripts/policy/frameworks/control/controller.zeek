##! This is a utility script that implements the controller interface for the
##! control framework.  It's intended to be run to control a remote Bro
##! and then shutdown.
##!
##! It's intended to be used from the command line like this::
##!
##!     zeek <scripts> frameworks/control/controller Control::host=<host_addr> Control::host_port=<host_port> Control::cmd=<command> [Control::arg=<arg>]

@load base/frameworks/control
@load base/frameworks/broker

module Control;

# Do some sanity checking and rework the communication nodes.
event zeek_init() &priority=5
	{
	# We know that some command was given because this script wouldn't be
	# loaded if there wasn't so we can feel free to throw an error here and
	# shutdown.
	if ( cmd !in commands )
		{
		Reporter::error(fmt("The '%s' control command is unknown.", cmd));
		terminate();
		}

	Broker::subscribe(Control::topic_prefix);
	Broker::peer(cat(host), host_port);
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

function send_control_request(topic: string)
	{
	switch ( cmd ) {
	case "id_value":
		if ( arg == "" )
			Reporter::fatal("The Control::id_value command requires that Control::arg also has some value.");

		Broker::publish(topic, Control::id_value_request, arg);
		break;

	case "peer_status":
		Broker::publish(topic, Control::peer_status_request);
		break;

	case "net_stats":
		Broker::publish(topic, Control::net_stats_request);
		break;

	case "shutdown":
		Broker::publish(topic, Control::shutdown_request);
		break;

	case "configuration_update":
		Broker::publish(topic, Control::configuration_update_request);
		break;

	default:
		Reporter::fatal(fmt("unhandled Control::cmd, %s", cmd));
		break;
	}
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string) &priority=-10
	{
	local topic = Control::topic_prefix + "/" + endpoint$id;

	if ( cmd == "configuration_update" )
		{
		# Send all &redef'able consts to the peer.
		local ids = configurable_ids();
		local publish_count = 0;

		for ( id in ids )
			{
			if ( Broker::publish_id(topic, id) )
				++publish_count;
			}

		Reporter::info(fmt("Control framework sent %d IDs", publish_count));
		}

	send_control_request(topic);
	}
