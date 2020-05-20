# @TEST-EXEC: zeek -b -r $TRACES/dhcp/dhcp_time_and_nameserver.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/dhcp

event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=5
	{
	if ( options?$time_offset )
		print "time_offset", options$time_offset;
	if ( options?$time_servers )
		print "timeserver_list", options$time_servers;
	if ( options?$name_servers )
		print "nameserver_list", options$name_servers;
	if ( options?$ntp_servers )
		print "ntpserver_list", options$ntp_servers;
	}
