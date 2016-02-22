##! This is a utility script that implements the controller interface for the
##! control framework.  It's intended to be run to control a remote Bro
##! and then shutdown.
##!
##! It's intended to be used from the command line like this::
##!
##!     bro <scripts> frameworks/control/controller Control::host=<host_addr> Control::host_port=<host_port> Control::cmd=<command> [Control::arg=<arg>]

@load base/frameworks/control
@load base/frameworks/broker/communication

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
	Broker::nodes["control"] = [$ip=host, $zone_id=zone_id,
	                                   $p=host_port, $connect=T];

	# Subscribe: subscribe to control-related response events
	local prefix = fmt("%sresponse/", Control::pub_sub_prefix);
	Broker::subscribe_to_events(prefix);

	# Publish: Register requests to control events with broker
	prefix = fmt("%srequest/", Control::pub_sub_prefix);
	for ( e in Control::controller_events )
		{
		local topic = string_cat(prefix, e);
		Broker::publish_topic(topic);
		Broker::auto_event(topic, lookup_ID(e));
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
	
event Control::shutdown_response() &priority=-10
	{
	event terminate_event();
	}
	
event Broker::outgoing_connection_established_event(peer_name: string) &priority=-10
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
	}
