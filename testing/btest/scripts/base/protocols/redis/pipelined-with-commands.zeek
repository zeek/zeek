# @TEST-DOC: Test Zeek parsing "pipelined" data responses
#
# @TEST-EXEC: zeek -Cr $TRACES/redis/pipeline-with-commands.pcap base/protocols/redis %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff redis.log

# Sometimes commands aren't serialized, like when pipelining. This still works! So we
# should handle this. This particular example has a few commands, amongst them a SET and
# a GET.
event Redis::set_command(c: connection, is_orig: bool,
    command: Redis::SetCommand)
	{
	print fmt("SET: %s %s", command$key, command$value);
	}

event Redis::get_command(c: connection, is_orig: bool,
    command: Redis::GetCommand)
	{
	print fmt("GET: %s", command);
	}
