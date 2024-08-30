# @TEST-DOC: Test make_event behavior.
#
# @TEST-EXEC: zeek -b %INPUT >out
#
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load frameworks/cluster/backend/nats

redef Cluster::backend = Cluster::CLUSTER_BACKEND_NATS;

function test_fun() { }
hook test_hook() { }
event test_event() { }
event test_event2(s: string) { }

function as_cluster_event(e: any): Cluster::Event
	{
	assert e is Cluster::Event;
	return e as Cluster::Event;
	}


event zeek_init() &priority=10
	{
	local e1 = Cluster::make_event(test_event);
	local ce1 = as_cluster_event(e1);
	print type_name(ce1$ev), ce1$args;

	local e2 = Cluster::make_event(test_event2, "abc");
	local ce2 = as_cluster_event(e2);
	print type_name(ce2$ev), ce2$args;
	}

event zeek_init() &priority=-10
	{
	local e = Cluster::make_event();
	}

event zeek_init() &priority=-11
	{
	local e = Cluster::make_event("a");
	}

event zeek_init() &priority=-12
	{
	local e = Cluster::make_event(test_fun);
	}

event zeek_init() &priority=-13
	{
	local e = Cluster::make_event(test_hook);
	}

event zeek_init() &priority=-14
	{
	local e = Cluster::make_event(test_event2);
	}

event zeek_init() &priority=-15
	{
	local e = Cluster::make_event(test_event2, "a", "b");
	}
