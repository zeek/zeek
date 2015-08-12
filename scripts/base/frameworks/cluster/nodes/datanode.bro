##! The datanode is passive (the workers connect to us), and once connected
##! the datanode registers for the events on the workers that are needed
##! to get the desired data from the workers.  This script will be 
##! automatically loaded if necessary based on the type of node being started.

@prefixes += cluster-datanode

## We are the datanode, so do local logging!
redef Log::enable_local_logging = T;

## Make sure that remote logging is disabled.
redef Log::enable_remote_logging = F;

## Log rotation interval.
redef Log::default_rotation_interval = 1hrs;

## Alarm summary mail interval.
redef Log::default_mail_alarms_interval = 24 hrs;

## Use the cluster's archives logging script.
redef Log::default_rotation_postprocessor_cmd = "archive-log";

## We're processing essentially *only* remote events.
redef max_remote_events_processed = 10000;

event bro_init() &priority = -10 
	{
	# Susbscribe to logs
	BrokerComm::advertise_topic("bro/log/");
	BrokerComm::subscribe_to_logs("bro/log/");

	## Subscribe to prefix
	local prefix = fmt("%s/data/request", Cluster::pub_sub_prefix);
	BrokerComm::advertise_topic(prefix);
	BrokerComm::subscribe_to_events(prefix);

	## Publish: datanode2manager_events, datanode2worker_events
	prefix = fmt("%s/manager/response", Cluster::pub_sub_prefix);
	Cluster::register_broker_events(prefix, Cluster::datanode2manager_events);
	prefix = fmt("%s/worker/response", Cluster::pub_sub_prefix);
	Cluster::register_broker_events(prefix, Cluster::datanode2worker_events);

	# Susbscribe to logs
	BrokerComm::subscribe_to_logs("bro/log/");
	}
