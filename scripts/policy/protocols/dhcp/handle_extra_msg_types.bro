##! Handlers for DHCP message types other than DHCPACK, which is handled in base/protocols/dhcp.
##! For networks that wish to get more details from their DHCP logs, at the expense
##! of a significantly higher log rate.

@load base/protocols/dhcp

module DHCP;

export {
	redef record Info += {
		## The value of the host name option, if seen
		host_name:	string		&log &optional;
		## The IP requested by the client, if any
		requested_ip:	addr		&log &optional;
		## The type of the DHCP message (DHCPOFFER, DHCPRELEASE, etc.)
		msg_type:	string		&log &optional;
	};

	#### Enabled by default
	
	## A boolean value to determine if DHCPREQUEST messages are logged.
	## Often useful to see client activity, and because host_name is often available.
	const log_dhcprequest = T &redef;

	## A boolean value to determine if DHCPDECLINE messages are logged.
	## A client declines a lease if it detects that the IP is already in use (usually via ARP).
	const log_dhcpdecline = T &redef;

	## A boolean value to determine if DHCPNAK messages are logged.
	## A server issues a DHCPNAK if a client DHCPREQUEST is invalid.
	const log_dhcpnak = T &redef;

	## A boolean value to determine if DHCPRELEASE messages are logged.
	## A client issues a DHCPRELEASE when it no longer needs the lease (e.g. it's shutting down).
	const log_dhcprelease = T &redef;

	#### Not enabled by default

	## A boolean value to determine if DHCPOFFER messages are logged.
	## Used to profile server -> client communication.
	const log_dhcpoffer = F &redef;
	
	## A boolean value to determine if DHCPDISCOVER messages are logged.
	## Used to profile broadcast client discovery requests.
	const log_dhcpdiscover = F &redef;
	
	## A boolean value to determine if DHCPINFORM messages are logged.
	## Used to profile clients attempting to request/renew specific IPs.
	const log_dhcpinform = F &redef;

}

event dhcp_offer(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string) &priority=5
	{
	if ( ! log_dhcpoffer )
		return;
	
	local info: Info;
	info$ts          = network_time();
	info$id          = c$id;
	info$uid         = c$uid;
	info$assigned_ip = reverse_ip(msg$yiaddr);
	info$lease_time  = lease;
	info$trans_id    = msg$xid;
	info$msg_type    = "DHCPOFFER";

	if ( msg$h_addr != "" )
		info$mac = msg$h_addr;

	if ( host_name != "" )
		info$host_name = host_name;

	c$dhcp = info;
	}

event dhcp_discover(c: connection, msg: dhcp_msg, req_addr: addr, host_name: string) &priority=5
	{
	if ( ! log_dhcpdiscover )
		return;
	
	local info: Info;
	info$ts           = network_time();
	info$id           = c$id;
	info$uid          = c$uid;
	info$requested_ip = req_addr;
	info$trans_id     = msg$xid;
	info$msg_type     = "DHCPDISCOVER";

	if ( msg$h_addr != "" )
		info$mac = msg$h_addr;

	if ( host_name != "" )
		info$host_name = host_name;

	c$dhcp = info;
	}

event dhcp_request(c: connection, msg: dhcp_msg, req_addr: addr, serv_addr: addr, host_name: string) &priority=5
	{
	if ( ! log_dhcprequest )
		return;
	
	local info: Info;
	info$ts           = network_time();
	info$id           = c$id;
	info$uid          = c$uid;
	info$requested_ip = req_addr;
	info$trans_id     = msg$xid;
	info$msg_type     = "DHCPREQUEST";

	if ( msg$h_addr != "" )
		info$mac = msg$h_addr;

	if ( host_name != "" )
		info$host_name = host_name;

	c$dhcp = info;
	}

event dhcp_decline(c: connection, msg: dhcp_msg, host_name: string) &priority=5
	{
	if ( ! log_dhcpdecline )
		return;
	
	local info: Info;
	info$ts           = network_time();
	info$id           = c$id;
	info$uid          = c$uid;
	info$trans_id     = msg$xid;
	info$msg_type     = "DHCPDECLINE";

	if ( msg$h_addr != "" )
		info$mac = msg$h_addr;

	if ( host_name != "" )
		info$host_name = host_name;

	c$dhcp = info;
	}

event dhcp_nak(c: connection, msg: dhcp_msg, host_name: string) &priority=5
	{
	if ( ! log_dhcpnak )
		return;
	
	local info: Info;
	info$ts           = network_time();
	info$id           = c$id;
	info$uid          = c$uid;
	info$trans_id     = msg$xid;
	info$msg_type     = "DHCPNAK";

	if ( msg$h_addr != "" )
		info$mac = msg$h_addr;

	if ( host_name != "" )
		info$host_name = host_name;

	c$dhcp = info;
	}

event dhcp_release(c: connection, msg: dhcp_msg, host_name: string) &priority=5
	{
	if ( ! log_dhcprelease )
		return;
	
	local info: Info;
	info$ts           = network_time();
	info$id           = c$id;
	info$uid          = c$uid;
	info$trans_id     = msg$xid;
	info$msg_type     = "DHCPRELEASE";

	if ( msg$h_addr != "" )
		info$mac = msg$h_addr;

	if ( host_name != "" )
		info$host_name = host_name;

	c$dhcp = info;
	}

event dhcp_inform(c: connection, msg: dhcp_msg, host_name: string) &priority=5
	{
	if ( ! log_dhcpinform )
		return;
	
	local info: Info;
	info$ts           = network_time();
	info$id           = c$id;
	info$uid          = c$uid;
	info$trans_id     = msg$xid;
	info$msg_type     = "DHCPINFORM";

	if ( msg$h_addr != "" )
		info$mac = msg$h_addr;

	if ( host_name != "" )
		info$host_name = host_name;

	c$dhcp = info;
	}

event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string) &priority=4
	{
	## For the sake of consistency, let's add msg_type to DHCPACK as well.
	c$dhcp$msg_type = "DHCPACK";
	## host_name is generally not in ACKs, but let's check anyway.
	if ( host_name != "" )
		c$dhcp$host_name = host_name;
	}

#### We log stuff at a lower priority, in case any other scripts would like to extend the Info record first.

event dhcp_offer(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string) &priority=1
	{
	if ( log_dhcpoffer )
		Log::write(DHCP::LOG, c$dhcp);
	}

event dhcp_discover(c: connection, msg: dhcp_msg, req_addr: addr, host_name: string) &priority=1
	{
	if ( log_dhcpdiscover )
		Log::write(DHCP::LOG, c$dhcp);
	}

event dhcp_request(c: connection, msg: dhcp_msg, req_addr: addr, serv_addr: addr, host_name: string) &priority=1
	{
	if ( log_dhcprequest )
		Log::write(DHCP::LOG, c$dhcp);
	}

event dhcp_decline(c: connection, msg: dhcp_msg, host_name: string) &priority=1
	{
	if ( log_dhcpdecline )
		Log::write(DHCP::LOG, c$dhcp);
	}

event dhcp_nak(c: connection, msg: dhcp_msg, host_name: string) &priority=1
	{
	if ( log_dhcpnak )
		Log::write(DHCP::LOG, c$dhcp);
	}

event dhcp_release(c: connection, msg: dhcp_msg, host_name: string) &priority=1
	{
	if ( log_dhcprelease )
		Log::write(DHCP::LOG, c$dhcp);
	}

event dhcp_inform(c: connection, msg: dhcp_msg, host_name: string) &priority=1
	{
	if ( log_dhcpinform )
		Log::write(DHCP::LOG, c$dhcp);
	}

