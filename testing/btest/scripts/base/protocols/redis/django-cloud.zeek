# @TEST-DOC: Test Redis traffic from a django app using Redis (in the cloud) as a cache
#
# @TEST-EXEC: zeek -Cr $TRACES/redis/django-cloud.pcap base/protocols/redis %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff redis.log

redef Redis::ports += { 10625/tcp,  };

event Redis::set_command(c: connection, is_orig: bool,
    command: Redis::SetCommand)
	{
	# Print the whole command because these have extra data that's worth capturing.
	print fmt("SET: %s %s expires in %d milliseconds", command$key, command$value,
	    command$px);
	}
