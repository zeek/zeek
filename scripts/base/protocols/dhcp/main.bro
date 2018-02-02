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

event bro_init() &priority=5
	{
	Log::create_stream(DHCP::LOG, [$columns=Info, $ev=log_dhcp, $path="dhcp"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_DHCP, ports);
	}

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=-5
	{
	if ( msg$m_type == 5 ) # DHCP_ACK
		{
		local info = Info($ts       = network_time(),
		                  $id       = c$id,
		                  $uid      = c$uid,
		                  $trans_id = msg$xid);

		if ( msg$h_addr != "" )
			info$mac = msg$h_addr;

		if ( reverse_ip(msg$yiaddr) != 0.0.0.0 )
			info$assigned_ip = reverse_ip(msg$yiaddr);
		else
			info$assigned_ip = c$id$orig_h;

		if ( options?$lease )
			info$lease_time  = options$lease;

		if ( options?$sub_opt )
			{
			for ( param in options$sub_opt )
				{
				local sub_opt = options$sub_opt[param];

				#if ( sub_opt$code == 1 ) 
				#	{
				#	print fmt("Relay Agent Information:");
				#	print fmt( "sub option: code=%d circuit id=%s",sub_opt$code,sub_opt$value );
				#	}
				
				if ( sub_opt$code == 2 )
					info$agent_remote_id = bytestring_to_hexstr(sub_opt$value);

				if ( sub_opt$code == 6 )
					info$subscriber_id = (sub_opt$value);
				}
			}

		c$dhcp = info;
		}
	}

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=-5
	{
	if ( msg$m_type == 5 ) # DHCP_ACK
		{
		Log::write(DHCP::LOG, c$dhcp);
		}
	}
