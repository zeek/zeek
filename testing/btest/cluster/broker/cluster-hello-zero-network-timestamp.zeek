# @TEST-DOC: Ensure Cluster::hello sent by a worker with a zero network time is observed with a zero network timestamp by the manager.
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: zeek -b --parse-only %INPUT
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b %INPUT"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b %INPUT"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/.stdout
# @TEST-EXEC: btest-diff ./worker-1/.stdout

redef allow_network_time_forward = F;
redef EventMetadata::add_network_timestamp = T;

event do_terminate()
	{
	terminate();
	}

event zeek_init()
	{
	# Set the manager's time to non-zero, the worker continues to be at 0.0.
	if ( Cluster::local_node_type() == Cluster::MANAGER )
		set_network_time(double_to_time(1748256346));
	}

event Cluster::hello(name: string, id: string)
	{
	print fmt("Cluster::hello name=%s is_remote_event=%s metadata=%s", name, is_remote_event(), EventMetadata::current_all());
	}

event Cluster::node_up(name: string, id: string)
	{
	print fmt("Cluster::node_up name=%s is_remote_event=%s metadata=%s", name, is_remote_event(), EventMetadata::current_all());

	if ( Cluster::local_node_type() == Cluster::MANAGER )
		Cluster::publish(Cluster::worker_topic, do_terminate);
	}

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
