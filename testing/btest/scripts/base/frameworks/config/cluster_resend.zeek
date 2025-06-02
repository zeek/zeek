# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager  zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: $SCRIPTS/wait-for-file manager/ready 30 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout
# @TEST-EXEC: btest-diff manager/config.log

# In this test we check if values get updated on a worker, even if they were set before the
# worker is present.

@load base/frameworks/config


redef Log::default_rotation_interval = 0secs;

export {
	option testport = 42/tcp;
	option teststring = "a";
	option testcount: count = 0;
}

global n = 0;

event ready_for_data()
	{
@if ( Cluster::node == "worker-1" )
	Config::set_value("testport", 44/tcp);
	Config::set_value("teststring", "b", "comment");
@endif
	}

global option_changed_count = 0;

function option_changed(ID: string, new_value: any, location: string): any
	{
	++option_changed_count;
	print "option changed", ID, new_value, location;

	if ( Cluster::node == "manager" && option_changed_count == 3 )
		system("touch ready");

	if ( Cluster::node == "worker-2" && option_changed_count == 3 )
		terminate();

	return new_value;
	}

event zeek_init() &priority=5
	{
	Option::set_change_handler("testport", option_changed, -100);
	Option::set_change_handler("teststring", option_changed, -100);
	Option::set_change_handler("testcount", option_changed, -100);
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )

global peer_count = 0;
event Cluster::node_up(name: string, id: string) &priority=-5
	{
	++peer_count;
	if ( peer_count == 1 )
		{
		Config::set_value("testcount", 1);
		Broker::publish(Cluster::worker_topic, ready_for_data);
		}
	}
@endif

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}
