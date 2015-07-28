##! Redefines some options common to all worker nodes within a Bro cluster.
##! In particular, worker nodes do not produce logs locally, instead they
##! send them off to a manager node for processing.

@prefixes += cluster-worker

## Don't do any local logging.
redef Log::enable_local_logging = F;

## Make sure that remote logging is enabled.
redef Log::enable_remote_logging = T;

redef Log::default_rotation_interval = 24hrs;

## Use the cluster's delete-log script.
redef Log::default_rotation_postprocessor_cmd = "delete-log";

@load misc/trim-trace-file
## Record all packets into trace file.
##
## Note that this only indicates that *if* we are recording packets, we want all
## of them (rather than just those the core deems sufficiently important).
## Setting this does not turn recording on. Use '-w <trace>' for that.
redef record_all_packets = T;

event bro_init() &priority = -10 
	{
	BrokerComm::subscribe_to_events(fmt("%s/proxy/request", Cluster::pub_sub_prefix));

	# Need to publish: proxy2manager_events, proxy2worker_events
	for ( e in Cluster::proxy2manager_events )
		BrokerComm::auto_event(fmt("%s/manager/response", Cluster::pub_sub_prefix), lookup_ID(e));

	for ( e in Cluster::proxy2worker_events )
		BrokerComm::auto_event(fmt("%s/worker/response", Cluster::pub_sub_prefix), lookup_ID(e));
	}
