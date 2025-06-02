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
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout
# @TEST-EXEC:

@load base/frameworks/storage/sync
@load base/frameworks/cluster
@load policy/frameworks/storage/backend/sqlite
@load policy/frameworks/cluster/experimental

global sqlite_data_written: event() &is_used;

@if ( Cluster::local_node_type() == Cluster::WORKER )

global backend: opaque of Storage::BackendHandle;

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

event sqlite_data_written()
	{
	print "sqlite_data_written";
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

event sqlite_data_written()
	{
	local e = Cluster::make_event(sqlite_data_written);
	Cluster::publish(Cluster::worker_topic, e);
	}

@endif

@if ( Cluster::node == "worker-1" )

event Cluster::Experimental::cluster_started()
	{
	local res = Storage::Sync::put(backend, [ $key="1234", $value="5678" ]);
	print Cluster::node, "put result", res;

	local e = Cluster::make_event(sqlite_data_written);
	Cluster::publish(Cluster::manager_topic, e);
	}

@endif
