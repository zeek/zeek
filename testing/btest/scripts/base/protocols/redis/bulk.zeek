# @TEST-DOC: Test Zeek parsing a trace file made with bulk-created SET commands
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -Cr $TRACES/redis/bulk-loading.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

# The bulk-loading functionality just sends the serialized form from some ruby
# code directly to the server, but it's useful to see if that trace might come
# up with something different. See:
# https://redis.io/docs/latest/develop/use/patterns/bulk-loading/

@load base/protocols/redis

event Redis::set_command(c: connection, command: Redis::SetCommand)
	{
	print fmt("SET: %s %s", command$key, command$value);
	}
