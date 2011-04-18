##! Script for logging passive DNS relpication data.  

## TODO: two queries within the create_expire with different results will
#        cause only one to be logged.

@load dns/base

module DNS;

export {
	global recent_requests: set[string] = set() &create_expire=10secs &synchronized;
}

event bro_init()
	{
	Log::add_filter(DNS, [
		$name="passive-replication",
		$path="passive-replication",
		$pred=function(rec: DNS::Info): bool 
			{ 
			if ( rec?$query && rec$query !in recent_requests )
				{
				add recent_requests[rec$query];
				return T;
				}
			return F;
			},
		$include=set("query", "replies")
		]);
	}