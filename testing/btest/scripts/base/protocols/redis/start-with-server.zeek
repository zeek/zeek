# @TEST-DOC: Test that Redis does not parse if it starts with the server data
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -r $TRACES/redis/start-with-server.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

@load base/protocols/redis

event Redis::command(c: connection, command: Redis::Command)
	{
	print "BAD", command;
	}

event Redis::reply(c: connection, dat: Redis::ReplyData)
	{
	print "BAD", dat;
	}

event Redis::error(c: connection, dat: Redis::ReplyData)
	{
	print "BAD", dat;
	}
