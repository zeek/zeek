# @TEST-DOC: Test Zeek with AUTH commands
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -r $TRACES/redis/auth.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

@load base/protocols/redis

event Redis::auth_command(c: connection, command: Redis::AuthCommand)
	{
	print "AUTH";
	if ( command?$username )
		print fmt("username: %s", command$username);
	else
		print "username: default";

	print fmt("password: %s", command$password);
	}
