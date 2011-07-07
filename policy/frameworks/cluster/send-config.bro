##! This is a utility script that sends the current values of all &redef'able 
##! consts to a remote Bro then sends the :bro:id:`configuration_update` event
##! and terminates processing.
##!
##! Intended to be used from the command line as in:
##!     bro Cluster::config_node=<node> <scripts> frameworks/cluster/send-config
##! 
##! The :bro:id:`config_node` value should contain the node name of one of the
##! nodes of the configured cluster.

@load frameworks/communication
@load frameworks/cluster

module Cluster;

export {
	## This is the name of the node configured in the cluster that the
	## updated configuration should be sent to.
	const config_node = "" &redef;

	## Variable IDs that are to be ignored by the update process.
	const ignore_ids: set[string] = {
		"Communication::nodes",
		"Cluster::config_node"
	};
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
		if ( ! t$redefinable || ! t$constant )
			next;

		send_id(p, id);
		++cnt;
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

function make_dest(tag: string, ip: addr, p: port)
	{
	Communication::nodes[fmt("%s-update", tag)] 
		= [$host=ip, $p=p, $sync=F, $class="update"];
	}

# This handler is executed after the other bro_inits() so that we can
# actually delete all previous destinations and fill the table ourselves.
event bro_init() &priority=-1
	{
	clear_table(Communication::nodes);

	for ( n in workers ) 
		make_dest(workers[n]$tag, workers[n]$ip, workers[n]$p);

	for ( n in proxies ) 
		make_dest(proxies[n]$tag, proxies[n]$ip, proxies[n]$p);

	make_dest(manager$tag, manager$ip, manager$p);
	}

event bro_init() &priority=-2
	{
	if ( config_node !in Communication::nodes )
		{
		if ( config_node == "" )
			print "You must supply a value to the Cluster::config_node variable.";
		else
			print fmt("Unknown peer '%s'", config_node);
		terminate();
		return;
		}

	Communication::connect_peer(config_node);
	}

