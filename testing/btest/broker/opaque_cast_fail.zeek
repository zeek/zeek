# @TEST-GROUP: broker
#
# @TEST-EXEC: zeek -b %INPUT >out 2>err
# @TEST-EXEC: btest-diff-remove-abspath out
# @TEST-EXEC: btest-diff-remove-abspath err

@load base/frameworks/broker

event zeek_init()
	{
	local k1: opaque of topk = topk_init(4);
	topk_add(k1, "a");

	local d = Broker::data(k1);

	# Casting the serialized payload to a different opaque type must be
	# rejected instead of silently producing a value of the wrong type.
	print d as opaque of sha1;
	}
