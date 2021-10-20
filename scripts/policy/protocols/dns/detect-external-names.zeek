##! This script detects names which are not within zones considered to be
##! local but resolving to addresses considered local.
##! The :zeek:id:`Site::local_zones` variable **must** be set appropriately for
##! this detection.

@load base/frameworks/notice
@load base/utils/site

module DNS;

export {
	redef enum Notice::Type += {
		## Raised when a non-local name is found to be pointing at a
		## local host.  The :zeek:id:`Site::local_zones` variable
		## **must** be set appropriately for this detection.
		External_Name,
		};
}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=-3
	{
	if ( |Site::local_zones| == 0 )
		return;

	# Check for responses from remote hosts that point at local hosts
	# but the name is not considered to be within a "local" zone.
	if ( Site::is_local_addr(a) &&            # referring to a local host
	     ! Site::is_local_name(ans$query) )   # name isn't in a local zone.
		{
		NOTICE([$note=External_Name,
		        $msg=fmt("%s is pointing to a local host - %s.", ans$query, a),
		        $conn=c,
		        $identifier=cat(a,ans$query)]);
		}
	}
