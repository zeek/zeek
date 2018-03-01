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
		# Not quite right to just blindly use 67 and 68 as the ports
		local id: conn_id = [$orig_h=rec$assigned_addr, $orig_p=68/udp,
		                     $resp_h=rec$server_addr, $resp_p=67/udp];

		if ( rec?$client_software && rec$assigned_addr != 255.255.255.255 )
			{
			Software::found(id, [$unparsed_version=rec$client_software,
			                     $host=rec$assigned_addr,
			                     $software_type=DHCP::CLIENT]);
			}
		
		if ( rec?$server_software )
			{
			Software::found(id, [$unparsed_version=rec$server_software,
			                     $host=rec$server_addr,
			                     $software_type=DHCP::SERVER]);
			}
		}
	}
