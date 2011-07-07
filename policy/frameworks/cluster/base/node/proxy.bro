
## Communication port setup.
redef Communication::listen_port_clear = Cluster::nodes[Cluster::node]$p;

## No packet capture on proxy.
redef interfaces = "";

## The proxy only syncs state; does not forward events.
redef forward_remote_events = F;
redef forward_remote_state_changes = T;

## Don't do any local logging.
redef Log::enable_local_logging = F;

## Make sure that remote logging is enabled.
redef Log::enable_remote_logging = T;

## Make the logging framework's default log rotation 1 hour.
redef Log::default_rotation_interval = 1hr;

## Use the cluster's delete-log script.
redef Log::default_rotation_postprocessor = "delete-log";

## Set our name.
redef peer_description = Cluster::node;

