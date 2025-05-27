# @TEST-DOC: Test Zeek parsing SET commands
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -r $TRACES/redis/set.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

@load base/protocols/redis

event Redis::set_command(c: connection, command: Redis::SetCommand)
	{
	print fmt("Key: %s Value: %s", command$key, command$value);
	}
