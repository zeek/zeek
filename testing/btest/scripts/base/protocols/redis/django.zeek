# @TEST-DOC: Test Redis traffic from a django app using Redis as a cache
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -Cr $TRACES/redis/django-cache.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff redis.log

@load base/protocols/redis

event Redis::set_command(c: connection, command: Redis::SetCommand)
	{
	# Print the whole command because these have extra data that's worth capturing.
	print fmt("SET: %s %s expires in %d milliseconds", command$key, command$value,
	    command$px);
	}
