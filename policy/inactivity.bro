# $Id: inactivity.bro 7073 2010-09-13 00:45:02Z vern $

@load port-name

const inactivity_timeouts: table[port] of interval = {
	# For interactive services, allow longer periods of inactivity.
	[[telnet, rlogin, ssh, ftp]] = 1 hrs,
} &redef;

function determine_inactivity_timeout(c: connection)
	{
	local service = c$id$resp_p;

	# Determine service (adapted from hot.bro)
	if ( c$orig$state == TCP_INACTIVE )
		{
		# We're seeing a half-established connection. Use the
		# service of the originator if it's well-known and the
		# responder isn't.
		if ( service !in port_names && c$id$orig_p in port_names )
			service = c$id$orig_p;
		}

	if ( service in inactivity_timeouts )
		set_inactivity_timeout(c$id, inactivity_timeouts[service]);
	}

event connection_established(c: connection)
	{
	determine_inactivity_timeout(c);
	}
