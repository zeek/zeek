##! This script feeds software detected through email into the software
##! framework.  Mail clients and webmail interfaces are the only thing
##! currently detected.
##!
##! TODO:
##!
##! * Find some heuristic to determine if email was sent through
##!   a MS Exchange webmail interface as opposed to a desktop client.

@load base/frameworks/software/main
@load base/protocols/smtp/main

module SMTP;

export {
	redef enum Software::Type += {
		MAIL_CLIENT,
		MAIL_SERVER,
		WEBMAIL_SERVER
	};

	redef record Info += {
		## Boolean indicator of if the message was sent through a
		## webmail interface.
		is_webmail: bool &log &default=F;
	};

	## Assuming that local mail servers are more trustworthy with the
	## headers they insert into message envelopes, this default makes Zeek
	## not attempt to detect software in inbound message bodies.  If mail
	## coming in from external addresses gives incorrect data in
	## the Received headers, it could populate your SOFTWARE logging stream
	## with incorrect data.  If you would like to detect mail clients for
	## incoming messages (network traffic originating from a non-local
	## address), set this variable to EXTERNAL_HOSTS or ALL_HOSTS.
	option detect_clients_in_messages_from = LOCAL_HOSTS;

	## A regular expression to match USER-AGENT-like headers to find if a
	## message was sent with a webmail interface.
	option webmail_user_agents =
	                     /^iPlanet Messenger/
	                   | /^Sun Java\(tm\) System Messenger Express/
	                   | /\(IMP\)/  # Horde Internet Messaging Program
	                   | /^SquirrelMail/
	                   | /^NeoMail/
	                   | /ZimbraWebClient/;
}

event mime_one_header(c: connection, h: mime_header_rec) &priority=4
	{
	if ( ! c?$smtp || ! c$smtp?$user_agent ) return;
	if ( h$name == "USER-AGENT" && webmail_user_agents in c$smtp$user_agent )
		c$smtp$is_webmail = T;
	}

event log_smtp(rec: Info)
	{
	# If the MUA provided a user-agent string, kick over to the software framework.
	# This is done here so that the "Received: from" path has a chance to be
	# built since that's where the IP address is pulled from.
	if ( rec?$user_agent )
		{
		local s_type = MAIL_CLIENT;
		local client_ip = rec$path[|rec$path|-1];
		if ( rec$is_webmail )
			{
			s_type = WEBMAIL_SERVER;
			# If the earliest received header indicates that the connection
			# was via HTTP, then that likely means the actual mail software
			# is installed on the second address in the path.
			if ( rec?$first_received && /via HTTP/ in rec$first_received )
				client_ip = rec$path[|rec$path|-2];
			}

		if ( addr_matches_host(rec$id$orig_h,
		                       detect_clients_in_messages_from) )
			{
			Software::found(rec$id, [$unparsed_version=rec$user_agent, $host=client_ip, $software_type=s_type]);
			}
		}
	}
