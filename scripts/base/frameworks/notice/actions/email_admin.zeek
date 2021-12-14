##! Adds a new notice action type which can be used to email notices
##! to the administrators of a particular address space as set by
##! :zeek:id:`Site::local_admins` if the notice contains a source
##! or destination address that lies within their space.

@load ../main
@load base/utils/site

module Notice;

export {
	redef enum Action += {
		## Indicate that the generated email should be addressed to the
		## appropriate email addresses as found by the
		## :zeek:id:`Site::get_emails` function based on the relevant
		## address or addresses indicated in the notice.
		ACTION_EMAIL_ADMIN
	};
}

hook notice(n: Notice::Info)
	{
	if ( |Site::local_admins| > 0 &&
	     ACTION_EMAIL_ADMIN in n$actions )
		{
		if ( n?$src && |Site::get_emails(n$src)| > 0 )
			add n$email_dest[Site::get_emails(n$src)];
		if ( n?$dst && |Site::get_emails(n$dst)| > 0 )
			add n$email_dest[Site::get_emails(n$dst)];
		}
	}
