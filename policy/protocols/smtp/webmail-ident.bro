##! Identify webmail interfaces.  This identification will be solely done 
##! with the USER-AGENT (or other) header unless not possible and will resort
##! to heuristics if necessary.
##!
##! TODO:
##!
##! * Find some heuristic to determine if email was sent through 
##!   a MS Exhange webmail interface as opposed to a desktop client.
##! 

@load smtp/base

module SMTP;

export {
	redef record Info += {
		## Boolean indicator of if the message was sent through a webmail 
		## interface.
		is_webmail: bool &log &default=F;
	};

	## A regular expression to match USER-AGENT-like headers to find if a 
	## message was sent with a webmail interface.
	const webmail_user_agents = 
	                     /^iPlanet Messenger/ 
	                   | /^Sun Java\(tm\) System Messenger Express/
	                   | /\(IMP\)/  # Horde Internet Messaging Program
	                   | /^SquirrelMail/
	                   | /^NeoMail/ 
	                   | /ZimbraWebClient/ &redef;
}


event smtp_data(c: connection, is_orig: bool, data: string) &priority=4
	{
	if ( c$smtp$current_header == "USER-AGENT" &&
	     webmail_user_agents in c$smtp$user_agent )
		c$smtp$is_webmail = T;
	}
