# @TEST-DOC: Test Zeek parsing pubsub commands
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -r $TRACES/redis/pubsub.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff redis.log

# Test pub/sub from Redis. This has two subscribers, one using a pattern. Then, the
# messages that were published get printed to output.

@load base/protocols/redis

event Redis::server_push(c: connection, data: Redis::ReplyData)
	{
	print "Got published data!", data$value;
	}
