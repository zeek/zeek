##! Redefines the options common to the data node within a Bro cluster.
##! In particular, the datanode is not meant to produce logs locally and it
##! does not forward events anywhere, it mainly synchronizes state between
##! worker nodes.

@prefixes += cluster-datanode

## The datanode only syncs state; does not forward events.
redef forward_remote_events = F;
redef forward_remote_state_changes = T;

## Don't do any local logging.
redef Log::enable_local_logging = F;

## Make sure that remote logging is enabled.
redef Log::enable_remote_logging = T;

redef Log::default_rotation_interval = 24hrs;

## Use the cluster's delete-log script.
redef Log::default_rotation_postprocessor_cmd = "delete-log";

