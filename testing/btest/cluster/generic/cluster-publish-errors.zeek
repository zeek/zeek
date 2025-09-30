# @TEST-DOC: Test errors of cluster bifs
#
# @TEST-EXEC: zeek --parse-only -b %INPUT
# @TEST-EXEC: zeek -b %INPUT frameworks/cluster/backend/broker
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stdout

module Cluster;

event ping1(c: count, how: string) &is_used
	{
	}

hook hook1(c: count, how: string) &is_used
	{
	}


event zeek_init()
	{
	# Fake the pool!
	init_pool_node(Cluster::proxy_pool, "proxy-1");
	mark_pool_node_alive(Cluster::proxy_pool, "proxy-1");
	}

event zeek_init() &priority=-1
	{
	print "Broker::make_event with Cluster::publish()";
	local be = Broker::make_event(ping1, 1, "make_event()");
	local r = Cluster::publish("topic", be);
	print "r=", r;
	}

event zeek_init() &priority=-2
	{
	print "Broker::make_event with Cluster::publish_hrw()";

	local be = Broker::make_event(ping1, 1, "make_event()");
	local r = Cluster::publish_hrw(Cluster::proxy_pool, "key", be);
	print "r=", r;
	}

event zeek_init() &priority=-3
	{
	print "Broker::make_event with Cluster::publish_rr()";
	local be = Broker::make_event(ping1, 1, "make_event()");
	local r = Cluster::publish_rr(Cluster::proxy_pool, "key", be);
	print "r=", r;
	}

type MyEvent: record {
	x: count &default=1;
};

event zeek_init() &priority=-4
	{
	print "Cluster::publish() with wrong event";
	local r = Cluster::publish("topic", MyEvent());
	print "r=", r;
	}

event zeek_init() &priority=-4
	{
	print "Cluster::publish_hrw() with wrong event";
	local r = Cluster::publish_hrw(Cluster::proxy_pool, "key", MyEvent());
	print "r=", r;
	}

event zeek_init() &priority=-4
	{
	print "Cluster::publish_rr() with wrong event";
	local r = Cluster::publish_rr(Cluster::proxy_pool, "key", MyEvent());
	print "r=", r;
	}
