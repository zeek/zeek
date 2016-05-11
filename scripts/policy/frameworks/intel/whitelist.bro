
@load base/frameworks/intel
@load base/frameworks/notice

module Intel;

export {
	redef record Intel::MetaData += {
		## Add a field to indicate if this is a whitelisted item.
		whitelist: bool &default=F;
	};
}

hook Intel::extend_match(info: Info, s: Seen, items: set[Item]) &priority=9
	{
	local whitelisted = F;
	for ( item in items )
		{
		if ( item$meta$whitelist )
			{
			whitelisted = T;
			break;
			}
		}
	
	if ( whitelisted )
		# Prevent logging
		break;
	}

