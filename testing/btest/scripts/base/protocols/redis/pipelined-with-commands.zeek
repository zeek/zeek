# @TEST-DOC: Test Zeek parsing "pipelined" data responses
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -r $TRACES/redis/pipeline-with-commands.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff redis.log

# Sometimes commands aren't serialized, like when pipelining. This still works! So we
# should handle this. This particular example has a few commands, amongst them a SET and
# a GET.

@load base/protocols/redis

event Redis::set_command(c: connection, command: Redis::SetCommand)
	{
	print fmt("SET: %s %s", command$key, command$value);
	}

event Redis::get_command(c: connection, key: string)
	{
	print fmt("GET: %s", key);
	}
