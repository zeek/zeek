##! Analyzes DHCP traffic in order to log DHCP leases given to clients.
##! This script ignores large swaths of the protocol, since it is rather
##! noisy on most networks, and focuses on the end-result: assigned leases.
##!
##! If you'd like to track known DHCP devices and to log the hostname
##! supplied by the client, see
##! :doc:`/scripts/policy/protocols/dhcp/known-devices-and-hostnames.bro`.

@load ./utils.bro

module DHCP;

export {
	redef enum Log::ID += { LOG };

	## The record type which contains the column fields of the DHCP log.
	type Info: record {
		## The earliest time at which a DHCP message over the
		## associated connection is observed.
		ts:			time			&log;
		## A unique identifier of the connection over which DHCP is
		## occurring.
		uid:			string			&log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:		 	conn_id			&log;
		## Client's hardware address.
		mac:		 	string			&log &optional;
		## Client's actual assigned IP address.
		assigned_ip:	 	addr			&log &optional;
		## IP address lease interval.
		lease_time:	 	interval		&log &optional;
		## A random number chosen by the client for this transaction.
		trans_id:	 	count			&log;
		## the message type
		msg_type:	 	string			&log &optional;
		## client ID
		client_id:		string			&log &optional;
		## the server ID
		server_id: 	 	addr			&log &optional;
		## the host name
		host_name:	 	string			&log &optional;
		## the subscriber id (if present)
		subscriber_id:	 	string			&log &optional;
		## the agent remote id (if present)
		agent_remote_id:	string			&log &optional;
	};

	## Event that can be handled to access the DHCP
	## record as it is sent on to the logging framework.
	global log_dhcp: event(rec: Info);
}

# Add the dhcp info to the connection record.
redef record connection += {
	dhcp: Info &optional;
};

# 67/udp is the server's port, 68/udp the client.
const ports = { 67/udp, 68/udp };
redef likely_server_ports += { 67/udp };

global info: Info;

event bro_init() &priority=5
	{
	Log::create_stream(DHCP::LOG, [$columns=Info, $ev=log_dhcp, $path="dhcp"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_DHCP, ports);
	}

event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string, reb_time: count, ren_time: count, sub_opt: dhcp_sub_opt_list) &priority=5
	{
	#local info: Info;
	info$ts          = network_time();
	info$id          = c$id;
	info$uid         = c$uid;
	info$lease_time  = lease;
	info$trans_id    = msg$xid;
	info$msg_type	 = message_types[msg$m_type];

	info$server_id	 = serv_addr;
	info$host_name   = host_name;

	if ( msg$h_addr != "" )
		info$mac = msg$h_addr;

	if ( reverse_ip(msg$yiaddr) != 0.0.0.0 )
		info$assigned_ip = reverse_ip(msg$yiaddr);
	else
		info$assigned_ip = c$id$orig_h;

	for (param in sub_opt)
	{
		#if ( sub_opt[param]$code == 1 ) 
                #{
                #print fmt("Relay Agent Information:");
                #print fmt( "sub option: code=%d circuit id=%s",sub_opt[param]$code,sub_opt[param]$value );
                #}
                if ( sub_opt[param]$code == 2 )
                        info$agent_remote_id = bytestring_to_hexstr(sub_opt[param]$value);

                if ( sub_opt[param]$code == 6 )
                        info$subscriber_id = (sub_opt[param]$value);
	}

	c$dhcp = info;
	}

event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string, reb_time: count, ren_time: count, sub_opt: dhcp_sub_opt_list) &priority=-5
	{
	Log::write(DHCP::LOG, c$dhcp);
	}

event dhcp_request(c: connection, msg: dhcp_msg, req_addr: addr, serv_addr: addr, host_name: string, c_id: dhcp_client_id, req_params: table[count] of count) &priority=5
	{
	info$ts          = network_time();
	info$id          = c$id;
	info$uid         = c$uid;
	info$trans_id    = msg$xid;
	info$msg_type	 = message_types[msg$m_type];
	info$server_id	 = serv_addr;
	info$host_name   = host_name;
	info$client_id 	 = c_id$hwaddr;

	c$dhcp = info;
	}

event dhcp_request(c: connection, msg: dhcp_msg, req_addr: addr, serv_addr: addr, host_name: string, c_id: dhcp_client_id, req_params: table[count] of count) &priority=-5
	{
	Log::write(DHCP::LOG, c$dhcp);
	}

event dhcp_discover(c: connection, msg: dhcp_msg, req_addr: addr, host_name: string, c_id: dhcp_client_id, req_params: table[count] of count) &priority=5
	{
	info$ts		= network_time();
	info$id		= c$id;
	info$uid	= c$uid;
	info$trans_id	= msg$xid;
	info$msg_type	= message_types[msg$m_type];
	info$host_name	= host_name;
	info$client_id	= c_id$hwaddr;

	c$dhcp = info;
	}

event dhcp_discover(c: connection, msg: dhcp_msg, req_addr: addr, host_name: string, c_id: dhcp_client_id, req_params: table[count] of count) &priority=-5
	{
	Log::write(DHCP::LOG, c$dhcp);
	}

