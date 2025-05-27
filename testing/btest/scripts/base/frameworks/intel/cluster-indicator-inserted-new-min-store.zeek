# @TEST-DOC: Verify behavior of Intel:indicator_inserted() and Intel::indicator_removed() when a worker node restarts.
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: zeek --parse-only %INPUT
# @TEST-EXEC: btest-bg-run manager ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: wait-for-file worker-1/DONE 30
# @TEST-EXEC: mv worker-1 worker-1-run-1
# @TEST-EXEC: rm -rf worker-1
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: wait-for-file worker-1/DONE 30
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: mv worker-1 worker-1-run-2

# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff manager/.stderr
# @TEST-EXEC: btest-diff worker-1-run-1/.stdout
# @TEST-EXEC: btest-diff worker-1-run-2/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout
#
@load policy/frameworks/cluster/experimental
@load base/frameworks/intel

# Ttoal of 5 unique indicators
# @TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
1.2.3.4	Intel::ADDR	source1	this host is bad	http://some-data-distributor.com/1
1.2.3.4	Intel::ADDR	source2	this host is bad	http://some-data-distributor.com/1
1.2.3.5	Intel::ADDR	source1	this host is bad	http://some-data-distributor.com/1
192.168.0.0/16	Intel::SUBNET	source1	this network is bad	http://some-data-distributor.com/2
putty	Intel::SOFTWARE	source1	this software is bad	http://some-data-distributor.com/2
putty	Intel::SOFTWARE	source2	this software is bad	http://some-data-distributor.com/2
putty2	Intel::SOFTWARE	source3	this software is bad	http://some-data-distributor.com/2
# @TEST-END-FILE

redef Log::default_rotation_interval = 0sec;

event Cluster::Experimental::cluster_started()
	{
	# Start reading the intel file on the manager once all workers are up.
	if ( Cluster::node == "manager" )
		{
		local source = "../intel.dat";
		Input::add_event([$source=source,
		                  $reader=Input::READER_ASCII,
		                  $mode=Input::REREAD,
		                  $name=cat("intel-", source),
		                  $fields=Intel::Item,
		                  $ev=Intel::read_entry,
		                  $error_ev=Intel::read_error]);
		}
	}

# Send by manager for termination purposes.
event do_terminate()
	{
	terminate();
	}

global worker1_down = 0;
global nodes_down = 0;

event Cluster::node_down(name: string, id: string)
	{
	++nodes_down;
	if ( name == "worker-1")
		++worker1_down;

	if ( worker1_down == 2 )
		Cluster::publish(Cluster::worker_topic, do_terminate);

	if ( nodes_down >= 3 )
		terminate();
	}

global total_indicators = 0;

hook Intel::indicator_inserted(indicator: string, indicator_type: Intel::Type)
	{
	print "Intel::indicator_inserted", indicator, indicator_type;
	++total_indicators;

	# Once worker-1 has seen all the 5 indicators, write a DONE file and terminate()
	if ( Cluster::node == "worker-1" && total_indicators == 5 )
		{
		if ( ! piped_exec("touch DONE", "") )
			exit(1);

		terminate();
		}
	}

hook Intel::indicator_removed(indicator: string, indicator_type: Intel::Type)
	{
	print "Intel::indicator_removed", indicator, indicator_type;
	}

module Intel;

# Internal events for easier grasping behavior.

event Intel::insert_indicator(item: Intel::Item) &priority=10
	{
	print "Intel::insert_indicator", item$indicator, item$indicator_type;
	}

event Intel::new_min_data_store(store: Intel::MinDataStore) &priority=10
	{
	print "Intel::new_min_data_store pre", cat(Intel::min_data_store);
	}

event Intel::new_min_data_store(store: Intel::MinDataStore) &priority=-10
	{
	print "Intel::new_min_data_store post", cat(Intel::min_data_store);
	}
