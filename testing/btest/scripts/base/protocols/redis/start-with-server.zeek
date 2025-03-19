# @TEST-DOC: Test that Redis does not parse if it starts with the server data
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -Cr $TRACES/redis/start-with-server.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

@load base/protocols/redis

event Redis::client_command(c: connection, command: Redis::Command)
	{
	print "BAD", command;
	}

event Redis::server_data(c: connection, dat: Redis::ServerData)
	{
	print "BAD", dat;
	}
