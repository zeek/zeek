##! This is the core Zeek script to support the notion of a cluster manager.
##!
##! The manager is passive (the workers connect to us), and once connected
##! the manager registers for the events on the workers that are needed
##! to get the desired data from the workers.  This script will be 
##! automatically loaded if necessary based on the type of node being started.

##! This is where the cluster manager sets it's specific settings for other
##! frameworks and in the core.

@prefixes += cluster-manager

## Don't do any local logging since the logger handles writing logs.
redef Log::enable_local_logging = F;

## Turn on remote logging since the logger handles writing logs.
redef Log::enable_remote_logging = T;

## Log rotation interval.
redef Log::default_rotation_interval = 24 hrs;

@if ( ! Supervisor::is_supervised() )
## Use the cluster's delete-log script.
redef Log::default_rotation_postprocessor_cmd = "delete-log";
@endif
