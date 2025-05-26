# @TEST-DOC: Smoke test sending metadata from a worker to a manager. The manager uses script level functions.
#
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo PublishEventMetadata
# @TEST-EXEC: cp -r %DIR/publish-event-metadata-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager ZEEKPATH=$ZEEKPATH:.. ZEEK_PLUGIN_PATH=`pwd` CLUSTER_NODE=manager zeek -b Demo::PublishEventMetadata %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. ZEEK_PLUGIN_PATH=`pwd` CLUSTER_NODE=worker-1 zeek -b Demo::PublishEventMetadata %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff manager/.stderr
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v PEER_UNAVAILABLE' btest-diff worker-1/.stderr

redef allow_network_time_forward = F;

@load frameworks/cluster/experimental

module App;

export {
	global test_event: event(c: count);

	redef enum EventMetadata::ID += {
		CUSTOM_METADATA_STRING = 4711,
		CUSTOM_METADATA_COUNT  = 4712,
		CUSTOM_METADATA_TABLE  = 4713,
	};
}

event App::test_event(c: count)
	{
	local mdv = EventMetadata::current_all();
	print fmt("App::test_event(%s) |mdv|=%s", c, |mdv|);
	for ( _, md in mdv )
		print md;

	print "custom metadata string", EventMetadata::current(App::CUSTOM_METADATA_STRING);
	print "custom metadata count", EventMetadata::current(App::CUSTOM_METADATA_COUNT);
	print "custom metadata table", EventMetadata::current(App::CUSTOM_METADATA_TABLE);

	if ( c == 4 )
		terminate();
	}

event zeek_init() &priority=20
	{
	assert EventMetadata::register(CUSTOM_METADATA_STRING, string);
	assert EventMetadata::register(CUSTOM_METADATA_COUNT, count);
	assert EventMetadata::register(CUSTOM_METADATA_TABLE, table[string] of string);

	Cluster::subscribe("topic1");
	Cluster::subscribe("topic2");
	Cluster::subscribe("topic3");
	Cluster::subscribe("topic4");
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node == "worker-1" )
		{
		Cluster::publish("topic1", test_event, 1);
		Cluster::publish("topic2", test_event, 2);
		Cluster::publish("topic3", test_event, 3);
		Cluster::publish("topic4", test_event, 4);
		}
	}

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
