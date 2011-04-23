
@load smtp/base
@load software

module SMTP;

redef enum Software::Type += {
	MAIL_CLIENT,
	MAIL_SERVER,
};

event log_smtp(rec: Info)
	{
	# If the MUA provided a user-agent string, kick over to the software framework.
	# This is done here so that the "Received: from" path has a chance to be
	# built since that's where the IP address is pulled from.
	# This falls apart a bit in the cases where a webmail client includes the 
	# IP address of the client in a header.  This will be compensated for 
	# later with more comprehensive webmail interface detection.
	if ( rec?$agent && rec?$received_from_originating_ip )
		{
		local s = Software::parse(rec$agent, rec$received_from_originating_ip, MAIL_CLIENT);
		Software::found(rec$id, s);
		}
	}
