# @TEST-DOC: Send any values and observe behavior using broker.
#
# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
#
# @TEST-EXEC: zeek -b --parse-only common.zeek manager.zeek worker.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/.stdout
# @TEST-EXEC: btest-diff ./worker-1/.stdout

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager"],
};
@TEST-END-FILE

# @TEST-START-FILE common.zeek
redef Log::default_rotation_interval = 0sec;

global finish: event() &is_used;
global ping: event(c: count, what: string, val: any) &is_used;
global pong: event(c: count, what: string, val: any) &is_used;
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global i = 0;
global pongs = 0;

event send_any()
	{
	if ( i > 4 )
		return;

	local val: any;
	if ( i == 0 )
		val = 1;
	else if ( i == 1 )
		val = "a string";
	else if ( i == 2 )
		val = 42/tcp;
	else if ( i == 3 )
		val = vector(1, 2, 3);
	else
		val = double_to_time(42.0);

	print "sending pings", i, type_name(val), val;
	Cluster::publish_hrw(Cluster::worker_pool, cat(i), ping, i, type_name(val), val);
	Broker::publish(Cluster::worker_topic, ping, i, type_name(val), val);
	local e = Cluster::make_event(ping, i, type_name(val), val);
	Cluster::publish_hrw(Cluster::worker_pool, cat(i), e);
	++i;

	schedule 0.05sec { send_any() };
	}

event pong(c: count, what: string, val: any)
	{
	++pongs;
	print "got pong", pongs, "for ping", c, what, type_name(val), val;

	# We send 5 pings in 3 different variations and
	# get 4 one pong for each.
	if ( pongs == 60 )
		Cluster::publish(Cluster::worker_topic, finish);
	}

event Cluster::node_up(name: string, id: string)
	{
	print "node_up", name;
	schedule 0.1sec { send_any() };
	}

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
# @TEST-END-FILE


# @TEST-START-FILE worker.zeek
@load ./common.zeek

event ping(c: count, what: string, val: any)
	{
	print "got ping", c, what, type_name(val), cat(val);
	Cluster::publish(Cluster::manager_topic, pong, c, what + " (cluster publish)", val);
	local e = Cluster::make_event(pong, c, what + " (cluster event  )", val);
	Cluster::publish(Cluster::manager_topic, e);

	Broker::publish(Cluster::manager_topic, pong, c, what + " (broker publish )", val);
	local be = Broker::make_event(pong, c, what + " (broker event   )", val);
	Broker::publish(Cluster::manager_topic, be);
	}

event finish()
	{
	print "got finish!";
	terminate();
	}
# @TEST-END-FILE
