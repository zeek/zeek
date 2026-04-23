# @TEST-DOC: Tests that large requests and responses get truncated
#
# @TEST-EXEC: zeek -b -r $TRACES/redis/large-requests-responses.pcap %INPUT 2>default.err
# @TEST-EXEC: mv redis.log redis-default.log
# @TEST-EXEC: btest-diff redis-default.log
# @TEST-EXEC: btest-diff default.err
#
# @TEST-EXEC: zeek -b -r $TRACES/redis/large-requests-responses.pcap Redis::max_value_size=10 %INPUT 2>smaller.err
# @TEST-EXEC: mv redis.log redis-smaller.log
# @TEST-EXEC: btest-diff redis-smaller.log
# @TEST-EXEC: btest-diff smaller.err
#
# @TEST-EXEC: zeek -b -r $TRACES/redis/large-requests-responses.pcap Redis::max_value_size=0 %INPUT
# Get only lines with at least 251 X's
# @TEST-EXEC: grep -E "X{251,}" redis.log > redis-uncapped.filtered.log
# @TEST-EXEC: btest-diff redis-uncapped.filtered.log

@load base/protocols/redis

# These will assert with the cap of 0, but that's ok since we don't diff stderr

event Redis::command(c: connection, cmd: Redis::Command)
	{
	for ( _, x in cmd$raw )
		assert |x| <= Redis::max_value_size;
	}

event Redis::reply(c: connection, reply: Redis::ReplyData)
	{
	if ( reply?$attributes )
		assert |reply$attributes| <= Redis::max_value_size;

	assert |reply$value| <= Redis::max_value_size;
	}
