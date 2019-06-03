# @TEST-EXEC: zeek -b -r $TRACES/tcp/rst-inject-rae.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

# Mostly just checking that c$resp$size isn't huge due to the injected
# RST packet being used to initialize sequence number in TCP analyzer.

event connection_state_remove(c: connection)
	{
	print c$id;
	print "orig:", c$orig;
	print "resp:", c$resp;
	}
