##! Tie together Radius authentication and DHCP messages
##! to find authentication happening to the port and then get the
##! IP address acquired by the host on that port.

@load base/frameworks/auth
@load base/protocols/dhcp
@load base/protocols/radius

module Radius;

event RADIUS::log_radius(rec: RADIUS::Info)
	{
	if ( rec?$username && rec?$mac )
		{
		local i = Auth::Info($ts=rec$ts,
		                     $username=rec$username,
		                     $endpoint=Auth::Endpoint($mac=rec$mac),
		                     $service=cat(rec$id$resp_h),
		                     $hardware_auth=T,
		                     $method="Radius");

		if ( rec$result == "failed" )
			i$success = F;

		Auth::do_login(i);
		}
	}

event DHCP::log_dhcp(rec: DHCP::Info)
	{
	local e: Auth::Endpoint;

	if ( rec?$assigned_ip )
		e$host = rec$assigned_ip;

	if ( rec?$mac )
		e$mac = rec$mac;

	local records_to_update = Auth::get_auths(e);
	if ( |records_to_update| > 0 )
		{
		for ( old_rec in records_to_update )
			{
			local new_rec = Auth::Info($ts=old_rec$ts, 
			                           $username=old_rec$username,
			                           $endpoint=e,
			                           $service=old_rec$service,
			                           $method=old_rec$method,
			                           $success=old_rec$success);

			Auth::modify_login(old_rec, new_rec);
			}
		}
	}