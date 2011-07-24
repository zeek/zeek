##! This is the core Bro script to support the notion of a cluster manager.
##!
##! The manager is passive (the workers connect to us), and once connected
##! the manager registers for the events on the workers that are needed
##! to get the desired data from the workers.

##! This is where the cluster manager sets it's specific settings for other
##! frameworks and in the core.

@prefixes += cluster-manager

## Turn off remote logging since this is the manager and should only log here.
redef Log::enable_remote_logging = F;

## Use the cluster's archive logging script.
redef Log::default_rotation_postprocessor = "archive-log";

## We're processing essentially *only* remote events.
redef max_remote_events_processed = 10000;

# Reraise remote notices locally.
event Notice::notice(n: Notice::Info)
	{
	if ( is_remote_event() )
		NOTICE(n);
	}
