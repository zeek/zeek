# @TEST-DOC: Test Zeek parsing pubsub commands in RESP3
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -r $TRACES/redis/pubsub-resp3.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

# Test pub/sub from Redis. This has two subscribers, one using a pattern. Then, the
# messages that were published get printed to output.

@load base/protocols/redis

event Redis::server_push(c: connection, data: Redis::ReplyData)
	{
	# The first 2 are SUBSCRIBE replies, the other 3 are message and pmessage
	print "Got published data!", data$value;
	}
