##! Analyzes DHCP traffic in order to log DHCP leases given to clients.
##! This script ignores large swaths of the protocol, since it is rather
##! noisy on most networks, and focuses on the end-result: assigned leases.
##! 
##! To enable further analysis and log output for DHCP, see the optional
##! scripts in the policy/protocols/dhcp directory.

@load ./utils.bro

module DHCP;

export {
	redef enum Log::ID += { LOG };

	## The record type which contains the column fields of the DHCP log.
	type Info: record {
		## The earliest time at which a DHCP message over the
		## associated connection is observed.
		ts:		time		&log;
		## A unique identifier of the connection over which DHCP is
		## occuring.
		uid:		string		&log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:		conn_id		&log;
		## Client's hardware address.
		mac:		string		&log &optional;
		## Client's actual assigned IP address.
		assigned_ip:	addr		&log &optional;
		## IP address lease interval.
		lease_time:	interval	&log &optional;
		## A random number choosen by the client for this transaction.
		trans_id:	count		&log;
	};

        ## Event that can be handled to access the DHCP
        ## record as it is sent on to the logging framework.
        global log_dhcp: event(rec: Info);
}

# Add the dhcp info to the connection record
redef record connection += {
	dhcp: Info &optional;
};

const ports = { 67/udp, 68/udp };
redef likely_server_ports += { 67/udp };

event bro_init() &priority=5
	{
	Log::create_stream(DHCP::LOG, [$columns=Info, $ev=log_dhcp]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_DHCP, ports);
	}

event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string) &priority=5
	{
	local info: Info;
	info$ts          = network_time();
	info$id          = c$id;
	info$uid         = c$uid;
	info$assigned_ip = reverse_ip(msg$yiaddr);
	info$lease_time  = lease;
	info$trans_id    = msg$xid;

	if ( msg$h_addr != "" )
		info$mac = msg$h_addr;
	
	c$dhcp = info;
	}

# We let policy scripts add stuff too, so we run this at a lower priority
event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string) &priority=1
	{
	Log::write(DHCP::LOG, c$dhcp);
	}
