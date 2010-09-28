# $Id: vars-sync-rcv.bro,v 1.1.2.1 2005/10/11 21:15:05 sommer Exp $

@load vars-init
@load vars-print

@load capture-events	
@load remote

	
redef Remote::destinations += {
    ["foo"] = [$host = 127.0.0.1, $events = /.*/, $connect=T, $sync=T]
};

