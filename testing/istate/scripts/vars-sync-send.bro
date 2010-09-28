# $Id: vars-sync-send.bro,v 1.1.2.1 2005/10/11 21:15:05 sommer Exp $
#

@load vars-init
@load vars-print
@load vars-modify

@load listen-clear

event remote_connection_handshake_done(p: event_peer)
	{
	modify();
	terminate_communication();
	}
			 
redef Remote::destinations += {
    ["foo"] = [$host = 127.0.0.1, $sync=T]
};

	
