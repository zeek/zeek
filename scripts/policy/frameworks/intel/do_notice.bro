
@load base/frameworks/intel
@load base/frameworks/notice

module Intel;

export {
	redef enum Notice::Type += {
		## Intel::Notice is a notice that happens when an intelligence 
		## indicator is denoted to be notice-worthy.
		Intel::Notice
	};

	redef record Intel::MetaData += {
		## A boolean value to allow the data itself to represent
		## if the indicator that this metadata is attached to 
		## is notice worthy.
		do_notice: bool &default=F;

		## Restrictions on when notices are created to only create
		## them if the *do_notice* field is T and the notice was
		## seen in the indicated location.
		if_in: Intel::Where &optional;
	};
}

event Intel::match(s: Seen, items: set[Item])
	{
	for ( item in items )
		{
		if ( item$meta$do_notice &&
		     (! item$meta?$if_in || s$where == item$meta$if_in) )
			{
			local n = Notice::Info($note=Intel::Notice,
			                       $msg=fmt("Intel hit on %s at %s", s$indicator, s$where),
			                       $sub=s$indicator);

			if ( s?$conn )
				n$conn = s$conn;

			NOTICE(n);
			}
		}
	}
