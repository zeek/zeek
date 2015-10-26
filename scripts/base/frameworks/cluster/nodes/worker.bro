##! Redefines some options common to all worker nodes within a Bro cluster.
##! In particular, worker nodes do not produce logs locally, instead they
##! send them off to a manager node for processing.

@load ../main

@prefixes += cluster-worker

## Don't do any local logging.
redef Log::enable_local_logging = F;

## Make sure that remote logging is enabled.
redef Log::enable_remote_logging = T;

redef Log::default_rotation_interval = 24hrs;

## Use the cluster's delete-log script.
redef Log::default_rotation_postprocessor_cmd = "delete-log";

@load misc/trim-trace-file
## Record all packets into trace file.
##
## Note that this only indicates that *if* we are recording packets, we want all
## of them (rather than just those the core deems sufficiently important).
## Setting this does not turn recording on. Use '-w <trace>' for that.
redef record_all_packets = T;

event bro_init() &priority=5
	{
	# Subsribe to prefix
	local prefix = fmt("%sworker/", Cluster::pub_sub_prefix);
	Broker::subscribe_to_events(prefix);

	# Publish: worker2manager_events, worker2datanode_events
	prefix = fmt("%smanager/", Cluster::pub_sub_prefix);
	Cluster::register_broker_events(prefix, Cluster::worker2manager_events);
	prefix = fmt("%sdata/", Cluster::pub_sub_prefix);
	Cluster::register_broker_events(prefix, Cluster::worker2datanode_events);
	}

event bro_init() &priority=-10
	{
	# Create clone of the master store
	Cluster::cluster_store = Broker::create_clone("cluster-store");
	}
