# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager  zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 40
# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-timestamps-and-sort btest-diff manager/intel.log
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

# @TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
1.2.3.4	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1234
1.2.3.4	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1234
e@mail.com	Intel::EMAIL	source1	Phishing email source	http://some-data-distributor.com/100000
# @TEST-END-FILE

@load base/frameworks/control
@load base/frameworks/intel
@load policy/frameworks/cluster/experimental
redef Log::default_rotation_interval=0sec;

module Intel;

@if ( Cluster::local_node_type() == Cluster::MANAGER )
redef Intel::read_files += { "../intel.dat" };
@endif

redef enum Intel::Where += {
	Intel::IN_A_TEST,
};

event do_it()
	{
	if ( Cluster::node == "manager" )
		{
		Broker::publish(Cluster::node_topic("worker-2"), do_it);
		return;
		}

	Intel::seen([$host=1.2.3.4, $where=Intel::IN_A_TEST]);
	Intel::seen([$indicator="e@mail.com", $indicator_type=Intel::EMAIL, $where=Intel::IN_A_TEST]);

	if ( Cluster::node == "worker-1" )
		Broker::publish(Cluster::node_topic("manager"), do_it);
	}

event start_it()
	{
	Broker::publish(Cluster::node_topic("worker-1"), do_it);
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node == "manager" )
		# Give more time for intel distribution.
		schedule 1sec { start_it() };
	}

event do_terminate()
	{
	terminate();
	}

global intel_hits=0;
event Intel::log_intel(rec: Intel::Info)
	{
	++intel_hits;
	# There should be 4 hits since each worker is "seeing" 2 things.
	if ( intel_hits == 4 )
		{
		# We're delaying shutdown for a second here to make sure that no other
		# matches happen (which would be wrong!).
		schedule 1sec { do_terminate() };
		}
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}
