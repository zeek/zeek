##! Tracks MAC address with hostnames seen in DHCP traffic. They are logged into
##! ``devices.log``.

@load policy/misc/known-devices

module Known;

export {
	redef record DevicesInfo += {
		## The value of the DHCP host name option, if seen.
		dhcp_host_name:	string		&log &optional;
	};
}

event dhcp_request(c: connection, msg: dhcp_msg, req_addr: addr, serv_addr: addr, host_name: string)
	{
	if ( msg$h_addr == "" )
		return;

	if ( msg$h_addr !in known_devices )
		{
		add known_devices[msg$h_addr];
		Log::write(Known::DEVICES_LOG, [$ts=network_time(), $mac=msg$h_addr, $dhcp_host_name=host_name]);
		}
	}

event dhcp_inform(c: connection, msg: dhcp_msg, host_name: string)
	{
	if ( msg$h_addr == "" )
		return;

	if ( msg$h_addr !in known_devices )
		{
		add known_devices[msg$h_addr];
		Log::write(Known::DEVICES_LOG, [$ts=network_time(), $mac=msg$h_addr, $dhcp_host_name=host_name]);
		}
	}
