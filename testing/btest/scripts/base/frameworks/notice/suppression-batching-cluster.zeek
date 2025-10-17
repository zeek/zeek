# @TEST-DOC: Run a four worker cluster
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_PROXY1_PORT
# @TEST-PORT: BROKER_PROXY2_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
# @TEST-PORT: BROKER_WORKER3_PORT
# @TEST-PORT: BROKER_WORKER4_PORT
#
# @TEST-EXEC: zeek --parse-only %INPUT
#
# @TEST-EXEC: btest-bg-run manager   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-2   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-3  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-3 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-4  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-4 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff proxy-2/.stdout
# @TEST-EXEC: btest-diff proxy-1/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout
# @TEST-EXEC: btest-diff worker-3/.stdout
# @TEST-EXEC: btest-diff worker-4/.stdout

@load base/frameworks/notice
@load policy/frameworks/cluster/experimental

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager"]  = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_MANAGER_PORT"))],
	["proxy-1"]  = [$node_type=Cluster::PROXY,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PROXY1_PORT")), $manager="manager"],
	["proxy-2"]  = [$node_type=Cluster::PROXY,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PROXY2_PORT")), $manager="manager"],
	["worker-1"] = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_WORKER1_PORT")), $manager="manager"],
	["worker-2"] = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_WORKER2_PORT")), $manager="manager"],
	["worker-3"] = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_WORKER3_PORT")), $manager="manager"],
	["worker-4"] = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_WORKER4_PORT")), $manager="manager"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

redef Notice::suppression_batch_max_size = 113;
redef Notice::suppression_batch_period = 7msec;

redef enum Notice::Type += {
	Test_Notice,
};

event done()
	{
	terminate();
	}

event do_notice(c: count)
	{
	if ( c == 0 )
		return;

	local identifier = fmt("%s-notice-c-%s", Cluster::node, c);

	NOTICE([$note=Test_Notice,
	        $msg="test notice!",
	        $identifier=identifier]);

	event do_notice(--c);
	}

global suppressions = 0;

global tbl: table[string] of count = {
	["worker-1"] = 0,
	["worker-2"] = 0,
	["worker-3"] = 0,
	["worker-4"] = 0,
} &ordered;

event Notice::begin_suppression(ts: time, suppress_for: interval, note: Notice::Type,
								identifier: string)
	{
	# print "begin suppression", suppress_for, note, identifier;
	++suppressions ;
	if ( suppressions % 1000 == 0 )
		print fmt("Have %d suppressions", suppressions);

	local worker = split_string(identifier, /-notice/)[0];
	++tbl[worker];

	# There's four workers, each creating 1000 notices that are suppressed,
	# so expect the manager to see them all.
	if ( suppressions == 4000 && Cluster::local_node_type() != Cluster::WORKER )
		{
		print tbl;
		if ( Cluster::local_node_type() == Cluster::MANAGER )
			{
			Broker::publish(Cluster::worker_topic, done);
			Broker::publish(Cluster::proxy_topic, done);
			terminate();
			}
		}
	}

module Notice;

event zeek_done()
	{
	print "Notice:suppressing", |suppressing|;
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::local_node_type() == Cluster::WORKER )
		event do_notice(1000);
	}
