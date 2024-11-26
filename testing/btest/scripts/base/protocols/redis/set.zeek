# @TEST-DOC: Test Zeek parsing SET commands
#
# @TEST-EXEC: zeek -Cr $TRACES/redis/set.pcap base/protocols/redis %INPUT >output
# @TEST-EXEC: btest-diff output

event Redis::set_command(c: connection, is_orig: bool,
    command: Redis::SetCommand)
	{
	print fmt("Key: %s Value: %s", command$key, command$value);
	}
