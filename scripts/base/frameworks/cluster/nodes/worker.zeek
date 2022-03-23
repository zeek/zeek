##! Redefines some options common to all worker nodes within a Zeek cluster.
##! In particular, worker nodes do not produce logs locally, instead they
##! send them off to a logger node for processing.

@prefixes += cluster-worker

## Don't do any local logging.
redef Log::enable_local_logging = F;

## Make sure that remote logging is enabled.
redef Log::enable_remote_logging = T;

redef Log::default_rotation_interval = 24hrs;

@if ( ! Supervisor::is_supervised() )
## Use the cluster's delete-log script.
redef Log::default_rotation_postprocessor_cmd = "delete-log";
@endif

@load misc/trim-trace-file
## Record all packets into trace file.
##
## Note that this only indicates that *if* we are recording packets, we want all
## of them (rather than just those the core deems sufficiently important).
## Setting this does not turn recording on. Use '-w <trace>' for that.
redef record_all_packets = T;
