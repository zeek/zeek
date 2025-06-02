# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager  "cp ../cluster-layout.zeek . && CLUSTER_NODE=manager  zeek -b %INPUT"
# @TEST-EXEC: btest-bg-run worker-1 "cp ../cluster-layout.zeek . && CLUSTER_NODE=worker-1 zeek -b --pseudo-realtime -C -r $TRACES/wikipedia.trace %INPUT"
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff manager/http.log


@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/cluster

@if ( Cluster::node == "worker-1" )
redef exit_only_after_terminate = T;
@endif

redef Log::default_rotation_interval = 0secs;

redef Log::default_scope_sep="_";

type Extension: record {
	write_ts: time &log;
	stream: string &log;
	system_name: string &log;
};

function add_extension(path: string): Extension
	{
	return Extension($write_ts    = network_time(),
	                 $stream      = path,
	                 $system_name = peer_description);
	}

redef Log::default_ext_func = add_extension;

event die()
	{
	terminate();
	}

event Pcap::file_done(path: string)
	{
	Broker::flush_logs();
	schedule 2sec { die() };
	}

event zeek_init()
	{
	if ( Cluster::node == "worker-1" )
		suspend_processing();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( Cluster::node == "worker-1" )
		continue_processing();
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	schedule 2sec { die() };
	}
