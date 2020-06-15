# @TEST-EXEC: zeek -b -r $TRACES/rdp/rdp-to-ssl.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

redef Weird::sampling_threshold = 2;

event my_event(c: connection)
	{
	Reporter::conn_weird("test!", c, "test2");
	Reporter::conn_weird("test!", c, "test2");
	Reporter::conn_weird("test!", c, "test2");
	Reporter::conn_weird("test!", c, "test2");
	}

event connection_state_remove(c: connection)
	{
	schedule 1sec { my_event(c) };
	}

event expired_conn_weird(name: string, id: conn_id, uid: string, addl: string)
	{
	print "expired_conn_weird", name, id, uid, addl;
	}
