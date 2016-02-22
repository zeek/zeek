##! This is the core Bro script to support the notion of a cluster log node.
##!
##! This script will be automatically loaded if necessary based on the type
##! of node being started.

##! This is where the cluster log node sets it's specific settings for other
##! frameworks and in the core.

## Turn on local logging.
redef Log::enable_local_logging = T;

## Turn off remote logging since this is the log node and should only log here.
redef Log::enable_remote_logging = F;

## Log rotation interval.
redef Log::default_rotation_interval = 1 hrs;

## Alarm summary mail interval.
redef Log::default_mail_alarms_interval = 24 hrs;

## Use the cluster's archive logging script.
redef Log::default_rotation_postprocessor_cmd = "archive-log";

## We're processing essentially *only* remote events.
redef max_remote_events_processed = 10000;
