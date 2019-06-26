# @TEST-EXEC: zeek -b -r $TRACES/dhcp/dhcp_time_and_nameserver.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/dhcp

event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=5
	{
	print "time_offset", options$time_offset;
	print "timeserver_list", options$time_servers;
	print "nameserver_list", options$name_servers;
	print "ntpserver_list", options$ntp_servers;
	}
