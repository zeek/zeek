# $Id: send-config.bro 6813 2009-07-07 18:54:12Z robin $
#
# Sends the current values of all &redef'able globals to a remote Bro
# and then terminates processing.
#
# Intended to be used from the command line as in:
#
# bro SendConfig::dst=<dst> <scripts> send-config

module SendConfig;

@load remote

export {
    const dst = "<no-destination-given>" &redef;
}

const ignore_ids = { "Remote::destinations", "SendConfig::dst" };

event terminate_event()
	{
	terminate_communication();
	}

event remote_connection_handshake_done(p: event_peer)
	{
	local peer = Remote::destinations[dst];

	if ( peer$host != p$host )
		return;

	# Send all &redef'able globals to peer.
	local globals = global_ids();
    local cnt = 0;
	for ( id in globals )
		{
        if ( id in ignore_ids )
			next;

		local t = globals[id];
		
		if ( ! t$redefinable )
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
	Remote::destinations[fmt("%s-update", tag)] 
		= [$host=ip, $p=p, $sync=F, $class="update"];
	}

# This handler is executed after the other bro_inits() so that we can
# actually delete all previous destinations and fill the table ourselves.
event bro_init() &priority=-1
	{
	clear_table(Remote::destinations);

	for ( n in BroCtl::workers ) 
		make_dest(BroCtl::workers[n]$tag, BroCtl::workers[n]$ip, BroCtl::workers[n]$p);

	for ( n in BroCtl::proxies ) 
		make_dest(BroCtl::proxies[n]$tag, BroCtl::proxies[n]$ip, BroCtl::proxies[n]$p);

	make_dest(BroCtl::manager$tag, BroCtl::manager$ip, BroCtl::manager$p);
	}

event bro_init() &priority=-2
	{
	if ( dst !in Remote::destinations )
		{
		print fmt("unknown destination %s", dst);
		terminate();
		return;
		}

	Remote::connect_peer(dst);
	}


