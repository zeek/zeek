@load base/frameworks/cluster
@load base/frameworks/logging 

module DHCPv6;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:             time      &log;
		uid:            string    &log;
		id:             conn_id   &log;
		transaction_id: count     &log;
		msg_type_req:   count     &log &optional;
		msg_type_rep:   count     &log &optional;
	};

	global relay_dhcpv6_event: event(msg_type: count, transaction_id: count, is_orig: bool, uid: string, id: conn_id, ts: time);
	global tx_table: table[count] of Info &create_expire=1 mins;
}

event zeek_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_DHCPV6, 546/udp);
	Analyzer::register_for_port(Analyzer::ANALYZER_DHCPV6, 547/udp);

	Log::create_stream(DHCPv6::LOG, [$columns=Info, $path="dhcpv6"]);
	}

event dhcpv6_message(c: connection, is_orig: bool, msg_type: count, transaction_id: count)
	{
	if ( ! Cluster::is_enabled() )
		{
		event DHCPv6::relay_dhcpv6_event(msg_type, transaction_id, is_orig, c$uid, c$id, network_time());
		return;
		}
	Cluster::publish_hrw(Cluster::WORKER, transaction_id, relay_dhcpv6_event, msg_type, transaction_id, is_orig, c$uid, c$id, network_time());
	}

event relay_dhcpv6_event(msg_type: count, transaction_id: count, is_orig: bool, uid: string, id: conn_id, ts: time)
	{
	if ( transaction_id !in tx_table )
		{
		local info: Info = [$ts=ts, $uid=uid, $id=id, $transaction_id=transaction_id];
		
		if ( id$orig_p == 546/udp )
			info$msg_type_req = msg_type;
		else
			info$msg_type_rep = msg_type;

		tx_table[transaction_id] = info;
		}
	else
		{
		local current_info = tx_table[transaction_id];
		
		if ( id$orig_p == 546/udp )
			current_info$msg_type_req = msg_type;
		else
			current_info$msg_type_rep = msg_type;

		Log::write(DHCPv6::LOG, current_info);
		
		delete tx_table[transaction_id];
		}
	}
