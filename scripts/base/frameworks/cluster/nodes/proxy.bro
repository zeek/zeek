
@prefixes += cluster-proxy

## The proxy only syncs state; does not forward events.
redef forward_remote_events = F;
redef forward_remote_state_changes = T;

## Don't do any local logging.
redef Log::enable_local_logging = F;

## Make sure that remote logging is enabled.
redef Log::enable_remote_logging = T;

## Use the cluster's delete-log script.
redef Log::default_rotation_postprocessor_cmd = "delete-log";

