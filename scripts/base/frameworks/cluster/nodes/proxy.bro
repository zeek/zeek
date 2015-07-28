##! Redefines the options common to all proxy nodes within a Bro cluster.
##! In particular, proxies are not meant to produce logs locally and they
##! do not forward events anywhere, they mainly synchronize state between
##! worker nodes.

@prefixes += cluster-proxy

## The proxy only syncs state; does not forward events.
redef forward_remote_events = F;
redef forward_remote_state_changes = T;

## Don't do any local logging.
redef Log::enable_local_logging = F;

## Make sure that remote logging is enabled.
redef Log::enable_remote_logging = T;

redef Log::default_rotation_interval = 24hrs;

## Use the cluster's delete-log script.
redef Log::default_rotation_postprocessor_cmd = "delete-log";

event bro_init() &priority = -10 
	{
	BrokerComm::subscribe_to_events(fmt("%s/proxy/request", Cluster::pub_sub_prefix));

	# Need to publish: proxy2manager_events, proxy2worker_events
	for ( e in Cluster::proxy2manager_events )
		BrokerComm::auto_event(fmt("%s/manager/response", Cluster::pub_sub_prefix), lookup_ID(e));

	for ( e in Cluster::proxy2worker_events )
		BrokerComm::auto_event(fmt("%s/worker/response", Cluster::pub_sub_prefix), lookup_ID(e));
	}
