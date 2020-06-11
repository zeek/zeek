# @TEST-EXEC: zeek -b -r $TRACES/rdp/rdp-to-ssl.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

event my_event(c: connection)
	{
	Reporter::conn_weird("test!", c, "test2");
	}

event connection_state_remove(c: connection)
	{
	schedule 1sec { my_event(c) };
	}

event conn_weird(name: string, c: connection, addl: string)
	{
	print "conn_weird", name, addl, c$id;
	}
