##! This is the core Bro script to support the notion of a cluster manager.
##! This is where the cluster manager sets it's specific settings for other
##! frameworks and in the core.

@load ../main

@prefixes += cluster-manager

## Enable local logging.
redef Log::enable_local_logging = T;

## Turn off remote logging since this is the manager and should only log here.
redef Log::enable_remote_logging = F;

## Log rotation interval.
redef Log::default_rotation_interval = 1 hrs;

## Alarm summary mail interval.
redef Log::default_mail_alarms_interval = 24 hrs;

## Use the cluster's archive logging script.
redef Log::default_rotation_postprocessor_cmd = "archive-log";

event bro_init() &priority=5
	{
	# Subscribe to prefix
	local prefix = fmt("%smanager/", Cluster::pub_sub_prefix);
	BrokerComm::advertise_topic(prefix);
	BrokerComm::subscribe_to_events(prefix);

	# Need to publish: manager2worker_events, manager2datanode_events
	prefix = fmt("%sworker/", Cluster::pub_sub_prefix);
	Cluster::register_broker_events(prefix, Cluster::manager2worker_events);
	prefix = fmt("%sdata/", Cluster::pub_sub_prefix);
	Cluster::register_broker_events(prefix, Cluster::manager2datanode_events);

	# Create clone of the master store
	Cluster::cluster_store = BrokerStore::create_clone("cluster-store");
	}
