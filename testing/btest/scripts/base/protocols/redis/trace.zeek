# @TEST-DOC: Test Zeek parsing a trace file through the Redis analyzer.
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -Cr $TRACES/redis/loop-redis.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff redis.log

@load base/protocols/redis

event Redis::set_command(c: connection, command: Redis::SetCommand)
	{
	print fmt("SET: %s %s", command$key, command$value);
	}

event Redis::get_command(c: connection, key: string)
	{
	print fmt("GET: %s", key);
	}
