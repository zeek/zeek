##! This is the core Bro script to support the notion of a cluster manager.
##! This is where the cluster manager sets it's specific settings for other
##! frameworks and in the core.

@prefixes += cluster-manager

## Don't do any local logging.
redef Log::enable_local_logging = F;

## Turn on remote logging since 
redef Log::enable_remote_logging = T;

## Log rotation interval.
redef Log::default_rotation_interval = 24 hrs;

## Alarm summary mail interval.
redef Log::default_mail_alarms_interval = 24 hrs;

## Use the cluster's delete-log script.
redef Log::default_rotation_postprocessor_cmd = "delete-log";

event bro_init() &priority = -10 
	{
	## Publish logs
	BrokerComm::publish_topic("bro/log/");

	## Subsribe to prefix
	local prefix = fmt("%s/manager/response", Cluster::pub_sub_prefix);
	BrokerComm::advertise_topic(prefix);
	BrokerComm::subscribe_to_events(prefix);

	# Need to publish: manager2worker_events, manager2datanode_events
	prefix = fmt("%s/worker/request", Cluster::pub_sub_prefix);
	Cluster::register_broker_events(prefix, Cluster::manager2worker_events);
	prefix = fmt("%s/data/request", Cluster::pub_sub_prefix);
	Cluster::register_broker_events(prefix, Cluster::manager2datanode_events);
	}
