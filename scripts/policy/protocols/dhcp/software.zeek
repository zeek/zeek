##! Software identification and extraction for DHCP traffic.

@load base/protocols/dhcp
@load base/frameworks/software

module DHCP;

export {
	redef enum Software::Type += {
		## Identifier for web servers in the software framework.
		DHCP::SERVER,
		## Identifier for web browsers in the software framework.
		DHCP::CLIENT,
	};

	redef record DHCP::Info += {
		## Software reported by the client in the `vendor_class` option.
		client_software: string &log &optional;
		## Software reported by the server in the `vendor_class` option.
		server_software: string &log &optional;
	};
}

event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=5
	{
	if ( options?$vendor_class )
		{
		if ( is_orig )
			log_info$client_software = options$vendor_class;
		else
			{
			log_info$server_software = options$vendor_class;
			Software::found(id, [$unparsed_version=options$vendor_class,
			                     $host=id$resp_h,
			                     $software_type=DHCP::SERVER]);
			}
		}
	}

event DHCP::log_dhcp(rec: DHCP::Info)
	{
	if ( rec?$assigned_addr && rec?$server_addr &&
	     (rec?$client_software || rec?$server_software) )
		{
		local id: conn_id = [$orig_h=rec$assigned_addr,
		                     $orig_p=rec$client_port,
		                     $resp_h=rec$server_addr,
		                     $resp_p=rec$server_port];

		if ( rec?$client_software && rec$assigned_addr != 255.255.255.255 )
			{
			Software::found(id, [$unparsed_version=rec$client_software,
			                     $host=rec$assigned_addr, $host_p=id$orig_p,
			                     $software_type=DHCP::CLIENT]);
			}

		if ( rec?$server_software )
			{
			Software::found(id, [$unparsed_version=rec$server_software,
			                     $host=rec$server_addr, $host_p=id$resp_p,
			                     $software_type=DHCP::SERVER]);
			}
		}
	}
