##! This is a utility script that sends the current values of all &redef'able 
##! consts to a remote Bro then sends the :bro:id:`configuration_update` event
##! and terminates processing.
##!
##! Intended to be used from the command line like this:
##!     bro Remote::config_node=<node> <scripts> support/remote/send-config
##! 
##! The :bro:id:`Remote::config_node` value should contain the node name of one of the
##! nodes of the configured communications.

@load frameworks/communication
@load support/remote

module Remote;

export {
	## This is the name of the node configured in the communication framework
	## that you want to send new variables to.
	const config_node = "" &redef;

	## Variable IDs that are to be ignored by the update process.
	const ignore_ids: set[string] = {
		# TODO: Bro crashes if it tries to send this ID.
		"Log::rotation_control",
	};
	
	## 
}

event terminate_event()
	{
	terminate_communication();
	}

event remote_connection_handshake_done(p: event_peer)
	{
	local peer = Communication::nodes[config_node];

	if ( peer$host != p$host )
		return;

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
		if ( t$constant && t$redefinable )
			{
			send_id(p, id);
			++cnt;
			}
		}

	print fmt("sent %d IDs", cnt);

	# Signal configuration update to peer.
	event configuration_update();
	
	# We can't terminate the communication right away here since the 
	# event configuration_update is only queued but not send at this
	# point. Therefore we raise another events which will trigger 
	# termination only after the previous has been raised.
	event terminate_event();
	}

event bro_init() &priority=-3
	{
	if ( config_node == "" )
		return;
	
	if ( config_node !in Communication::nodes )
		{
		print fmt("Unknown peer '%s'", config_node);
		terminate();
		return;
		}

	local n = Communication::nodes[config_node];
	n$connect=T;
	n$sync=F;
	n$class="control";
	Communication::nodes = table(["control"] = n);
	}
