# Test in cluster mode, the manager produces the cluster.log
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: zeek -b --parse-only %INPUT
# @TEST-EXEC: btest-bg-run manager  "cp ../cluster-layout.zeek . && CLUSTER_NODE=manager  zeek -b %INPUT"
# @TEST-EXEC: btest-bg-run worker-1 "cp ../cluster-layout.zeek . && CLUSTER_NODE=worker-1 zeek -b --pseudo-realtime -C -r $TRACES/dhcp/dhcp_ack_subscriber_id_and_agent_remote_id.trace %INPUT"

# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff manager/dhcp.log

@load base/protocols/dhcp
@load base/frameworks/broker
@load base/frameworks/cluster
@load base/frameworks/logging

redef Log::default_rotation_interval = 0secs;
redef Log::default_rotation_postprocessor_cmd = "echo";
redef exit_only_after_terminate = T;

redef Broker::disable_ssl = T;
redef Cluster::manager_is_logger = T;

event terminate_me() {
	terminate();
}

@if ( Cluster::local_node_type() == Cluster::WORKER )
event zeek_init()
	{
	suspend_processing();
	}

event Cluster::node_up(name: string, id: string)
	{
	print "node_up", name;
	continue_processing();
	}

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
	{
	print "dhcp_message", c$uid;
	}

event Pcap::file_done(path: string)
	{
	print "file_done";
	terminate();
	}
@else

event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=5
	{
	print "DHCP::aggregate_msgs", ts, uid;
	}

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
@endif
