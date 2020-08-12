##! This script extends the built in notice code to implement the IP address
##! dropping functionality.

@load base/frameworks/notice/main
@load base/frameworks/netcontrol
@load policy/frameworks/netcontrol/catch-and-release

module Notice;

export {
	redef record Info += {
		## Indicate if the $src IP address was dropped and denied
		## network access.
		dropped:  bool           &log &default=F;
	};
}

hook notice(n: Notice::Info) &priority=-5
	{
	if ( ACTION_DROP in n$actions )
		{
		local ci = NetControl::get_catch_release_info(n$src);
		if ( ci$watch_until == double_to_time(0) )
			{
			# we have not seen this one yet. Drop it.
			local addl = n?$msg ? fmt("ACTION_DROP: %s", n?$msg) : "ACTION_DROP";
			local res = NetControl::drop_address_catch_release(n$src, addl);
			n$dropped = res$watch_until != double_to_time(0);
			}
		}
	}
