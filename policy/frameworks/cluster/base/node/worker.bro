
## Set the port that this worker is supposed to listen on.
redef Communication::listen_port_clear = Cluster::nodes[Cluster::node]$p;

## Don't do any local logging.
redef Log::enable_local_logging = T;

## Make sure that remote logging is enabled.
redef Log::enable_remote_logging = T;

## Make the logging framework's default log rotation 1 hour.
redef Log::default_rotation_interval = 1hr;

## Use the cluster's delete-log script.
redef Log::default_rotation_postprocessor = "delete-log";

## Give the worker a name.
redef peer_description = Cluster::node;

## Record all packets into trace file.
# TODO: should we really be setting this to T?
redef record_all_packets = T;
