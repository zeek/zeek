# @TEST-EXEC: zeek -b -r $TRACES/rdp/rdpeudp-handshake-fail.pcap %INPUT >out
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff out

@load base/protocols/rdp
@load base/protocols/conn

event rdpeudp_syn(c: connection)
	{
	print "rdpeudp_syn", c$id;
	}

event rdpeudp_synack(c: connection)
	{
	print "rdpeudp_synack", c$id;
	}

event rdpeudp_established(c: connection, version: count)
	{
	print "rdpeudp_established", c$id, version;
	}

event rdpeudp_data(c: connection, is_orig: bool, version: count, data: string)
	{
	print fmt("rdpeudp_data is_orig: %s, version %d, data: %s", is_orig, version, data);
	}
