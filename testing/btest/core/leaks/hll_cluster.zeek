# Needs perftools support.
#
# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: zeek -m %INPUT>out
# @TEST-EXEC: btest-bg-run manager-1 HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 zeek -m %INPUT
# @TEST-EXEC: btest-bg-run worker-1 HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 zeek -m runnumber=1 %INPUT
# @TEST-EXEC: btest-bg-run worker-2 HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 zeek -m runnumber=2 %INPUT
# @TEST-EXEC: btest-bg-wait 60
#
# @TEST-EXEC: btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

global hll_data: event(data: opaque of cardinality);

@if ( Cluster::local_node_type() == Cluster::WORKER )

event zeek_init()
	{
	Broker::auto_publish(Cluster::manager_topic, hll_data);
	}

global runnumber: count &redef; # differentiate runs

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	local c = hll_cardinality_init(0.01, 0.95);

	local add1 = 2001;
	local add2 = 2002;
	local add3 = 2003;

	if ( runnumber == 1 )
		{
		hll_cardinality_add(c, add1);
		hll_cardinality_add(c, add2);
		hll_cardinality_add(c, add3);
		hll_cardinality_add(c, 1000);
		hll_cardinality_add(c, 1001);
		hll_cardinality_add(c, 101);
		hll_cardinality_add(c, 1003);
		hll_cardinality_add(c, 1004);
		hll_cardinality_add(c, 1005);
		hll_cardinality_add(c, 1006);
		hll_cardinality_add(c, 1007);
		hll_cardinality_add(c, 1008);
		hll_cardinality_add(c, 1009);
		print "This value should be around 13:";
		print hll_cardinality_estimate(c);
		}
	else if ( runnumber == 2 )
		{
		hll_cardinality_add(c, add1);
		hll_cardinality_add(c, add2);
		hll_cardinality_add(c, add3);
		hll_cardinality_add(c, 1);
		hll_cardinality_add(c, 101);
		hll_cardinality_add(c, 2);
		hll_cardinality_add(c, 3);
		hll_cardinality_add(c, 4);
		hll_cardinality_add(c, 5);
		hll_cardinality_add(c, 6);
		hll_cardinality_add(c, 7);
		hll_cardinality_add(c, 8);
		print "This value should be about 12:";
		print hll_cardinality_estimate(c);
		}

	event hll_data(c);

	terminate();
	}

@endif

@if ( Cluster::local_node_type() == Cluster::MANAGER )

global result_count = 0;
global hll: opaque of cardinality;

event zeek_init()
	{
	hll = hll_cardinality_init(0.01, 0.95);
	}

event hll_data(data: opaque of cardinality)
	{
	hll_cardinality_merge_into(hll, data);
	++result_count;

	if ( result_count == 2 )
		{
		print "This value should be about 21:";
		print hll_cardinality_estimate(hll);
		terminate();
		}
	}

@endif
