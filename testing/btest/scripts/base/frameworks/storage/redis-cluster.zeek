# @TEST-DOC: Tests Redis storage in a cluster environment

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT
# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3

# @TEST-EXEC: btest-bg-run redis-server run-redis-server ${REDIS_PORT%/tcp}
# @TEST-EXEC: btest-bg-run manager-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout
# @TEST-EXEC:

@load base/frameworks/storage/sync
@load base/frameworks/cluster
@load policy/frameworks/storage/backend/redis
@load policy/frameworks/cluster/experimental

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1"],
};
@TEST-END-FILE

global redis_data_written: event() &is_used;

@if ( Cluster::local_node_type() == Cluster::WORKER )

global backend: opaque of Storage::BackendHandle;
type str: string;

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv(
	    "REDIS_PORT")), $key_prefix="testing" ];

	local open_res = Storage::Sync::open_backend(Storage::REDIS, opts, str, str);
	backend = open_res$value;
	}

event redis_data_written()
	{
	print "redis_data_written";
	local res = Storage::Sync::get(backend, "1234");
	print Cluster::node, res;
	Storage::Sync::close_backend(backend);
	terminate();
	}

@else

global node_count: count = 0;

event Cluster::node_down(name: string, id: string)
	{
	++node_count;
	if ( node_count == 2 )
		terminate();
	}

event redis_data_written()
	{
	local e = Cluster::make_event(redis_data_written);
	Cluster::publish(Cluster::worker_topic, e);
	}

@endif

@if ( Cluster::node == "worker-1" )

event Cluster::Experimental::cluster_started()
	{
	local res = Storage::Sync::put(backend, [ $key="1234", $value="5678" ]);
	print Cluster::node, "put result", res;

	local e = Cluster::make_event(redis_data_written);
	Cluster::publish(Cluster::manager_topic, e);
	}

@endif
