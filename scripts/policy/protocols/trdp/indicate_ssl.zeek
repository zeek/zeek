@load base/protocols/trdp
@load base/protocols/ssl

module TRDP;

export {
	redef record TRDP::Info += {
		## Flag the connection if it was seen over SSL.
		ssl: bool &log &default=F;
	};
}

event ssl_established(c: connection)
	{
	if ( c?$trdp )
		{
		c$trdp$ssl = T;
		}
	}