# client-heartbeat.bro
# Send heartbeat events to a remote server
# $Id: client-heartbeat.bro,v 1.3 2007/02/26 07:03:20 jason Exp $

# load remote communications
@load remote

global bro_heartbeat_interval = 15 min &redef;

# heartbeat server (ip address)
global bro_heartbeat_server: addr = 127.0.0.1 &redef;

# name of this host (optional, its not used)
global myhostname = "foo.example.com" &redef; 
global myip = 127.0.0.1 &redef; 

######################################################################
# Shouldn't need to modifiy anything below this
# (Unless your not using SSL, then you will)
######################################################################

# who to 'heartbeat' to (i.e. the heartbeat server)
# usually hostname-service (i.e. host.lbl.gov-syslog)
redef Remote::destinations += { 
 	["server-heartbeat"] = [$host=bro_heartbeat_server, 
 		$retry=60 sec, $connect=T, $ssl=F],
 };

# do nothing in the client
event heartbeat_event( ts: double, myip: addr, hostname: string )
    {
    # intentionally left empty
    }


# call heartbeat_event and schedule ourselves to run again
event send_heartbeat_event()
	{
	local hb_host = fmt ("%s", get_event_peer());
    # NOT USED
    local foo: double = 0.0;
	event heartbeat_event( foo, myip, myhostname );
	schedule bro_heartbeat_interval  { send_heartbeat_event() };
	}

# stick us in the queue to run
event bro_init()
	{
# waiting till gethostname is put into production bro.bif
#	if myhostname == "")
#	{
#		myhostname = gethostname();
#	}
	schedule bro_heartbeat_interval { send_heartbeat_event() };
	}
