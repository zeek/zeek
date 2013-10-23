##! Allows configuration of a pager email address to which notices can be sent.

@load ../main

module Notice;

export {
	redef enum Action += {
		## Indicates that the notice should be sent to the pager email
		## address configured in the :bro:id:`Notice::mail_page_dest`
		## variable.
		ACTION_PAGE
	};
	
	## Email address to send notices with the :bro:enum:`Notice::ACTION_PAGE`
	## action.
	const mail_page_dest = "" &redef;
}

hook notice(n: Notice::Info) &priority=-5
	{
	if ( ACTION_PAGE in n$actions )
		email_notice_to(n, mail_page_dest, F);
	}
