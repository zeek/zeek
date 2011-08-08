
@prefixes += cluster-worker

## Don't do any local logging.
redef Log::enable_local_logging = F;

## Make sure that remote logging is enabled.
redef Log::enable_remote_logging = T;

## Use the cluster's delete-log script.
redef Log::default_rotation_postprocessor_cmd = "delete-log";

## Record all packets into trace file.
# TODO: should we really be setting this to T?
redef record_all_packets = T;

# Workers need to have a filter for the notice log which doesn't 
# do remote logging since we forward the notice event directly.
event bro_init()
	{
	Log::add_filter(Notice::NOTICE,
		[
		 $name="cluster-worker",
		 $pred=function(rec: Notice::Info): bool { return F; }
		]
	);
	}
