# $Id: events-rcv.bro,v 1.1.2.1 2005/10/07 01:59:12 sommer Exp $

@load tcp
@load http-request
@load http-reply
@load http-header
@load http-body
@load http-abstract
	
@load capture-events	
@load remote
	
redef peer_description = "events-rcv";
	
redef Remote::destinations += {
    ["foo"] = [$host = 127.0.0.1, $events = /.*/, $connect=T]
};

