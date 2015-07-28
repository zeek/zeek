##! This is the core Bro script to support the notion of a cluster manager.
##!
##! The manager is passive (the workers connect to us), and once connected
##! the manager registers for the events on the workers that are needed
##! to get the desired data from the workers.  This script will be 
##! automatically loaded if necessary based on the type of node being started.

##! This is where the cluster manager sets it's specific settings for other
##! frameworks and in the core.

@prefixes += cluster-manager

## Turn off remote logging since this is the manager and should only log here.
redef Log::enable_remote_logging = F;

## Log rotation interval.
redef Log::default_rotation_interval = 1 hrs;

## Alarm summary mail interval.
redef Log::default_mail_alarms_interval = 24 hrs;

## Use the cluster's archive logging script.
redef Log::default_rotation_postprocessor_cmd = "archive-log";

## We're processing essentially *only* remote events.
redef max_remote_events_processed = 10000;

event bro_init() &priority = -10 
	{
	BrokerComm::subscribe_to_events(fmt("%s/manager/response", Cluster::pub_sub_prefix));

	# Need to publish: manager2worker_events, manager2proxy_events
	for ( e in Cluster::manager2worker_events )
		BrokerComm::auto_event(fmt("%s/worker/request", Cluster::pub_sub_prefix), lookup_ID(e));
		
	for (e in Cluster::manager2proxy_events )
		BrokerComm::auto_event(fmt("%s/proxy/request", Cluster::pub_sub_prefix), lookup_ID(e));
	}
