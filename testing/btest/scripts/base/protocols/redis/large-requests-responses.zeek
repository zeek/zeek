# @TEST-DOC: Tests that large requests and responses get truncated
# @TEST-EXEC: zeek -b -r $TRACES/redis/large-requests-responses.pcap %INPUT
# @TEST-EXEC: btest-diff redis.log
# @TEST-EXEC: btest-diff .stderr

@load base/protocols/redis

const MAX_REDIS_BYTES = 250;

event Redis::command(c: connection, cmd: Redis::Command)
	{
	for ( _, x in cmd$raw )
		assert |x| <= MAX_REDIS_BYTES;
	}

event Redis::reply(c: connection, reply: Redis::ReplyData)
	{
	if ( reply?$attributes )
		assert |reply$attributes| <= MAX_REDIS_BYTES;

	assert |reply$value| <= MAX_REDIS_BYTES;
	}
