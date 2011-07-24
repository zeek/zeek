
module Notice;

export {
	redef enum Action += {
		## Indicate that the generated email should be addressed to the 
		## appropriate email addresses as found in the 
		## :bro:id:`Site::addr_to_emails` variable based on the relevant 
		## address or addresses indicated in the notice.
		ACTION_EMAIL_ADMIN
	};
}

event notice(n: Notice::Info) &priority=-5
	{
	if ( |Site::local_admins| > 0 &&
	     ACTION_EMAIL_ADMIN in n$actions )
		{
		local email = "";
		if ( n?$src && |Site::get_emails(n$src)| > 0 )
			email = fmt("%s, %s", email, Site::get_emails(n$src));
		if ( n?$dst && |Site::get_emails(n$dst)| > 0 )
			email = fmt("%s, %s", email, Site::get_emails(n$dst));
		
		if ( email != "" )
			email_notice_to(n, email, T);
		}
	}