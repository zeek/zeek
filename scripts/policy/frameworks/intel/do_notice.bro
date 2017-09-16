##! This script enables notice generation for intelligence matches.

@load base/frameworks/intel
@load base/frameworks/notice

module Intel;

export {
	redef enum Notice::Type += {
		## This notice is generated when an intelligence
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
				$msg = fmt("Intel hit on %s at %s", s$indicator, s$where),
				$sub = s$indicator);
			local service_str = "";

			if ( s?$conn )
				{
				n$conn = s$conn;

				# Add identifier composed of indicator, originator's and responder's IP,
				# without considering the direction of the flow.
				local intel_id = s$indicator;
				if( s$conn?$id )
					{
					if( s$conn$id$orig_h < s$conn$id$resp_h)
						intel_id = cat(intel_id, s$conn$id$orig_h, s$conn$id$resp_h);
					else
						intel_id = cat(intel_id, s$conn$id$resp_h, s$conn$id$orig_h);
					}
				n$identifier = intel_id;

				if ( s$conn?$service )
					{
					for ( service in s$conn$service )
						service_str = cat(service_str, service, " ");
					}
				}

			# Add additional information to the generated mail
			local mail_ext = vector(
				fmt("Service: %s\n", service_str),
				fmt("Intel source: %s\n", item$meta$source));
			n$email_body_sections = mail_ext;

			NOTICE(n);
			}
		}
	}
