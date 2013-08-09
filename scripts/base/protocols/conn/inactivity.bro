##! Adjust the inactivity timeouts for interactive services which could
##! very possibly have long delays between packets.

module Conn;

export {
	## Define inactivity timeouts by the service detected being used over
	## the connection.
	const analyzer_inactivity_timeouts: table[Analyzer::Tag] of interval = {
		# For interactive services, allow longer periods of inactivity.
		[[Analyzer::ANALYZER_SSH, Analyzer::ANALYZER_FTP]] = 1 hrs,
	} &redef;
	
	## Define inactivity timeouts based on common protocol ports.
	const port_inactivity_timeouts: table[port] of interval = {
		[[21/tcp, 22/tcp, 23/tcp, 513/tcp]] = 1 hrs,
	} &redef;
	
}
	
event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count)
	{
	if ( atype in analyzer_inactivity_timeouts )
		set_inactivity_timeout(c$id, analyzer_inactivity_timeouts[atype]);
	}

event connection_established(c: connection)
	{
	local service_port = c$id$resp_p;
	if ( c$orig$state == TCP_INACTIVE )
		{
		# We're seeing a half-established connection. Use the
		# service of the originator if it's well-known and the
		# responder isn't.
		if ( service_port !in likely_server_ports && c$id$orig_p in likely_server_ports )
			service_port = c$id$orig_p;
		}

	if ( service_port in port_inactivity_timeouts )
		set_inactivity_timeout(c$id, port_inactivity_timeouts[service_port]);
	}
