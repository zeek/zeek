# @TEST-GROUP: broker
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/frameworks/broker

event zeek_init()
	{
	local k1: opaque of topk = topk_init(4);
	topk_add(k1, "a");
	topk_add(k1, "b");

	local d = Broker::data(k1);
	print "d type:", type_name(d);

	# Casting the serialized payload to its actual opaque type must succeed.
	local k2 = d as opaque of topk;
	print "good cast:", type_name(k2), topk_get_top(k2, 5);
	}
