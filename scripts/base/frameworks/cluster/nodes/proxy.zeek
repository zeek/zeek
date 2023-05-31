##! Redefines the options common to all proxy nodes within a Zeek cluster.
##! In particular, proxies are not meant to produce logs locally and they
##! do not forward events anywhere, they mainly synchronize state between
##! worker nodes.

@prefixes += cluster-proxy

## Don't do any local logging.
redef Log::enable_local_logging = F;

## Make sure that remote logging is enabled.
redef Log::enable_remote_logging = T;

redef Log::default_rotation_interval = 24hrs;

@if ( ! Supervisor::is_supervised() )
## Use the cluster's delete-log script.
redef Log::default_rotation_postprocessor_cmd = "delete-log";
@endif

