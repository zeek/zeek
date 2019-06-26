# @TEST-EXEC: zeek -C -r $TRACES/tls/chrome-34-google.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

event connection_pending(c: connection)
	{
	print current_time(), "Connection pending", c$id, c$history;
	}
