# @TEST-DOC: Verify Intel::indicator_inserted() and Intel::indicator_removed() in a cluster setup with three different types of indicators.
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b ../addr-indicator.zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b ../addr-indicator.zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b ../addr-indicator.zeek %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: mkdir addr-indicator/; cp -R manager worker-1 worker-2 ./addr-indicator/
# @TEST-EXEC: btest-diff addr-indicator/manager/.stdout
# @TEST-EXEC: btest-diff addr-indicator/worker-1/.stdout
# @TEST-EXEC: btest-diff addr-indicator/worker-2/.stdout
#
# @TEST-EXEC: rm -rf manager worker-1 worker-2
#
# @TEST-EXEC: btest-bg-run manager ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b ../subnet-indicator.zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b ../subnet-indicator.zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b ../subnet-indicator.zeek %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: mkdir subnet-indicator/; cp -R manager worker-1 worker-2 ./subnet-indicator/
# @TEST-EXEC: btest-diff subnet-indicator/manager/.stdout
# @TEST-EXEC: btest-diff subnet-indicator/worker-1/.stdout
# @TEST-EXEC: btest-diff subnet-indicator/worker-2/.stdout

# @TEST-EXEC: rm -rf manager worker-1 worker-2
#
# @TEST-EXEC: btest-bg-run manager ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b ../software-indicator.zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b ../software-indicator.zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b ../software-indicator.zeek %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: mkdir software-indicator/; cp -R manager worker-1 worker-2 ./software-indicator/
# @TEST-EXEC: btest-diff software-indicator/manager/.stdout
# @TEST-EXEC: btest-diff software-indicator/worker-1/.stdout
# @TEST-EXEC: btest-diff software-indicator/worker-2/.stdout
#
# @TEST-EXEC: rm -rf manager worker-1 worker-2

@load policy/frameworks/cluster/experimental
@load base/frameworks/intel

redef Log::default_rotation_interval = 0sec;

# @TEST-START-FILE addr-indicator.zeek
@load base/frameworks/intel

const test_intel_type = Intel::ADDR;

event remove_indicator(value: string, source: string)
	{
	print"remove_addr", value, source;
	Intel::remove([$indicator=value, $indicator_type=Intel::ADDR, $meta=[$source=source]], F);
	}

event insert_indicator(value: string, source: string)
	{
	print "insert_addr", value, source;
	Intel::insert([$indicator=value, $indicator_type=Intel::ADDR, $meta=[$source=source]]);
	}
# @TEST-END-FILE

# @TEST-START-FILE subnet-indicator.zeek
@load base/frameworks/intel

const test_intel_type = Intel::SUBNET;

event remove_indicator(value: string, source: string)
	{
	value = value + "/32";  # make the IP value from generic code a valid subnet
	print"remove_subnet", value, source;
	Intel::remove([$indicator=value, $indicator_type=Intel::SUBNET, $meta=[$source=source]], F);
	}

event insert_indicator(value: string, source: string)
	{
	value = value + "/32";  # make the IP value from generic code a valid subnet
	print "insert_subnet", value , source;
	Intel::insert([$indicator=value, $indicator_type=Intel::SUBNET, $meta=[$source=source]]);
	}
# @TEST-END-FILE

# @TEST-START-FILE software-indicator.zeek
@load base/frameworks/intel

const test_intel_type = Intel::SOFTWARE;

event remove_indicator(value: string, source: string)
	{
	value = "software-" + value;
	print"remove_software", value, source;
	Intel::remove([$indicator=value, $indicator_type=Intel::SOFTWARE, $meta=[$source=source]], F);
	}

event insert_indicator(value: string, source: string)
	{
	value = "software-" + value;
	print "insert_software", value , source;
	Intel::insert([$indicator=value, $indicator_type=Intel::SOFTWARE, $meta=[$source=source]]);
	}
# @TEST-END-FILE

# Helper event for printing on manager and worker.
event next_round()
	{
	print "====";
	if ( Cluster::node == "manager" )
		Cluster::publish(Cluster::worker_topic, next_round);
	}

# Send by manager for termination purposes.
event do_terminate()
	{
	terminate();
	}

event publish_do_terminate()
	{
	print "publish_do_terminate()";
	Cluster::publish(Cluster::worker_topic, do_terminate);
	}

# Ensure the manager terminates eventually.
global nodes_down = 0;
event Cluster::node_down(name: string, id: string)
	{
	++nodes_down;
	if ( nodes_down >= 2)
		terminate();
	}

# Gets the ball rolling
event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::local_node_type() == Cluster::MANAGER )
		event insert_indicator("1.2.3.4", "from-manager");
	}

global indicators_inserted: table[Intel::Type] of count &default=0;
global indicator_removed: table[Intel::Type] of count &default=0;

hook Intel::indicator_inserted(indicator: string, indicator_type: Intel::Type)
	{
	print "Intel::indicator_inserted", indicator, indicator_type;
	++indicators_inserted[indicator_type];

	# If worker-1 sees the first addr indicator (1.2.3.4), it re-inserts
	# it with a different source (from-worker) and also inserts a second
	# indicatore 1.2.3.5 with with sources "from-worker" and "from-manager";
	if ( Cluster::node == "worker-1" )
		{
		if ( indicators_inserted[test_intel_type] == 1 || indicators_inserted[test_intel_type] == 3 )
			{
			event insert_indicator("1.2.3.4", "from-worker");
			event insert_indicator("1.2.3.5", "from-worker");
			event insert_indicator("1.2.3.5", "from-manager");
			}
		}

	# Once worker-2 has observed two or four indicators, it removes
	# all of them again!
	if ( Cluster::node == "worker-2" )
		{
		if ( indicators_inserted[test_intel_type] == 2 || indicators_inserted[test_intel_type] == 4 )
			{
			event remove_indicator("1.2.3.4", "from-manager");
			event remove_indicator("1.2.3.5", "from-manager");
			event remove_indicator("1.2.3.4", "from-worker");
			event remove_indicator("1.2.3.5", "from-worker");
			}
		}
	}

hook Intel::indicator_removed(indicator: string, indicator_type: Intel::Type)
	{
	print "Intel::indicator_removed", indicator, indicator_type;
	++indicator_removed[indicator_type];
	if ( Cluster::node == "manager" )
		{
		if ( indicator_removed[test_intel_type] == 2 )
			{
			# Trigger another round of inserts at the workers!
			event next_round();
			event insert_indicator("1.2.3.4", "from-manager");
			}
		else if ( indicator_removed[test_intel_type] == 4 )
			{
			event publish_do_terminate();
			}
		}
	}
