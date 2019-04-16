##! If an RDP session is "upgraded" to SSL, this will be indicated
##! with this script in a new field added to the RDP log.

@load base/protocols/rdp
@load base/protocols/ssl

module RDP;

export {
	redef record RDP::Info += {
		## Flag the connection if it was seen over SSL.
		ssl: bool &log &default=F;
	};
}

event ssl_established(c: connection)
	{
	if ( c?$rdp )
		{
		c$rdp$ssl = T;
		}
	}