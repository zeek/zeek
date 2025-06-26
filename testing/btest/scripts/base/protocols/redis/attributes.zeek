# @TEST-DOC: Test Redis protocol handling with replies with attributes
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -r $TRACES/redis/attr.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff redis.log

# IMPORTANT: The test data was made synthetically, since real commands that
# return attributes may be version-specific. Real traffic would be better.

@load base/protocols/redis

event Redis::reply(c: connection, data: Redis::ReplyData)
	{
	if ( ! data?$attributes )
		print "Got data:", data$value;
	else
		print "Got data:", data$value, "with attributes:", data$attributes;
	}
