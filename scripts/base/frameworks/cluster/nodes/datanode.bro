##! The datanode is passive (the workers connect to us), and once connected
##! the datanode registers for the events on the workers that are needed
##! to get the desired data from the workers.  This script will be
##! automatically loaded if necessary based on the type of node being started.

@load ../main

@prefixes += cluster-datanode

## We are the datanode, so don't do local logging!
redef Log::enable_local_logging = F;

## Make sure that remote logging is enabled.
redef Log::enable_remote_logging = T;

## Log rotation interval.
redef Log::default_rotation_interval = 24hrs;

## Alarm summary mail interval.
redef Log::default_mail_alarms_interval = 24 hrs;

## Use the cluster's archives logging script.
redef Log::default_rotation_postprocessor_cmd = "delete-log";

## We're processing essentially *only* remote events.
redef max_remote_events_processed = 10000;

event bro_init() &priority=5
	{
	# Subscribe to prefix
	local prefix = fmt("%sdata/", Cluster::pub_sub_prefix);
	Broker::subscribe_to_events(prefix);

	# Publish: datanode2manager_events, datanode2worker_events
	prefix = fmt("%smanager/", Cluster::pub_sub_prefix);
	Cluster::register_broker_events(prefix, Cluster::datanode2manager_events);
	prefix = fmt("%sworker/", Cluster::pub_sub_prefix);
	Cluster::register_broker_events(prefix, Cluster::datanode2worker_events);

	# Create the master store
	Cluster::cluster_store = BrokerStore::create_master("cluster-store");
	}

