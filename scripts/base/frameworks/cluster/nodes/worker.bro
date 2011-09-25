@prefixes += cluster-worker

# Load the script for local site configuration for the worker nodes.
@load site/local-worker

## Don't do any local logging.
redef Log::enable_local_logging = F;

## Make sure that remote logging is enabled.
redef Log::enable_remote_logging = T;

## Use the cluster's delete-log script.
redef Log::default_rotation_postprocessor_cmd = "delete-log";

## Record all packets into trace file.
##
## Note that this only indicates that *if* we are recording packets, we want all
## of them (rather than just those the core deems sufficiently important). Setting
## this does not turn recording on. Use '-w <trace>' for that.
redef record_all_packets = T;
