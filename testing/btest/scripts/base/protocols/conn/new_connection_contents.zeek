# @TEST-EXEC: zeek -r $TRACES/irc-dcc-send.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

event new_connection_contents(c: connection)
	{
	print fmt("new_connection_contents for %s", cat(c$id));
	}
