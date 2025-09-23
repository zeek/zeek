# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-no-logger.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: zeek --parse-only -b %INPUT>out
# @TEST-EXEC: btest-bg-run manager  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager  zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT runnumber=1
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT runnumber=2
# @TEST-EXEC: btest-bg-wait 30
#
# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@load zeromq-test-bootstrap

redef Log::default_rotation_interval = 0secs;

global hll_data: event(data: opaque of cardinality) &is_used;

global do_terminate: event() &is_used;

@if ( Cluster::local_node_type() == Cluster::WORKER )

global runnumber: count &redef; # differentiate runs

event do_terminate()
	{
	terminate();
	}

event Cluster::node_up(name: string, id: string)
	{
	# Workers see each other, but we only want
	# to publish to the manager.
	if ( name != "manager" )
		return;

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

	Cluster::publish(Cluster::manager_topic, hll_data, c);
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
		Cluster::publish(Cluster::worker_topic, do_terminate);
		}
	}

# The manager runs the XPUB/XSUB proxy, so it waits until
# the workers are gone before shutting down.
global nodes_down = 0;
event Cluster::node_down(name: string, id: string)
	{
	++nodes_down;
	if ( nodes_down == 2 )
		terminate();
	}
@endif
