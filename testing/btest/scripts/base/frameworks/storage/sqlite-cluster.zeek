# @TEST-DOC: Tests SQLite storage in a cluster environment
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"

# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .

# @TEST-EXEC: btest-bg-run manager ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait -k 10
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout
# @TEST-EXEC:

@load base/frameworks/storage/sync
@load base/frameworks/cluster
@load policy/frameworks/storage/backend/sqlite
@load policy/frameworks/cluster/experimental

redef Storage::expire_interval = 2 secs;

global sqlite_data_written: event() &is_used;

@if ( Cluster::local_node_type() == Cluster::WORKER )

global backend: opaque of Storage::BackendHandle;
global key1: string = "key1234";
global value1: string = "value1234";

global key2: string = "key2345";
global value2: string = "value2345";

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$sqlite = [ $database_path="../test.sqlite", $table_name="testing" ];

	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts, string, string);
	if ( open_res$code != Storage::SUCCESS ) {
		print fmt("Worker %s failed to open backend: %s", Cluster::node, open_res$error_str);
		terminate();
	}

	backend = open_res$value;
	}

event check_removed()
	{
	local res = Storage::Sync::get(backend, key1);
	print Cluster::node, "get result 1 after expiration", res;

	res = Storage::Sync::get(backend, key2);
	print Cluster::node, "get result 2 after expiration", res;

	Storage::Sync::close_backend(backend);
	terminate();
	}

event sqlite_data_written()
	{
	print "sqlite_data_written";
	schedule 5secs { check_removed() };
	}

@else

global node_count: count = 0;

event Cluster::node_down(name: string, id: string)
	{
	++node_count;
	if ( node_count == 2 )
		terminate();
	}

event sqlite_data_written()
	{
	local e = Cluster::make_event(sqlite_data_written);
	Cluster::publish(Cluster::worker_topic, e);
	}

@endif

@if ( Cluster::node == "worker-1" )

event Cluster::Experimental::cluster_started()
	{
	local res = Storage::Sync::put(backend, [ $key=key1, $value=value1 ]);
	print Cluster::node, "put result 1", res;

	res = Storage::Sync::put(backend, [ $key=key2, $value=value2, $expire_time=2 sec ]);
	print Cluster::node, "put result 2", res;

	local e = Cluster::make_event(sqlite_data_written);
	Cluster::publish(Cluster::manager_topic, e);
	}

@endif
