# @TEST-EXEC: zeek -b -C -r $TRACES/icmp/5-pings.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

global update_count = 0;
global connection_status_update_interval = 1sec;

event new_connection(c: connection)
	{ print "new_connection", c$id; }

event connection_status_update(c: connection)
	{ print "connection_status_update", ++update_count, c$id; }
