##! Load this script to enable global log output to an ElasticSearch database.

module LogElasticSearch;

export {
	## An elasticsearch specific rotation interval.
	const rotation_interval = 3hr &redef;

	## Optionally ignore any :bro:type:`Log::ID` from being sent to
	## ElasticSearch with this script.
	const excluded_log_ids: set[Log::ID] &redef;

	## If you want to explicitly only send certain :bro:type:`Log::ID` 
	## streams, add them to this set.  If the set remains empty, all will 
	## be sent.  The :bro:id:`LogElasticSearch::excluded_log_ids` option
	## will remain in effect as well.
	const send_logs: set[Log::ID] &redef;
}

event bro_init() &priority=-5
	{
	if ( server_host == "" )
		return;
	
	for ( stream_id in Log::active_streams )
		{
		if ( stream_id in excluded_log_ids ||
		     (|send_logs| > 0 && stream_id !in send_logs) )
			next;

		local filter: Log::Filter = [$name = "default-es",
		                             $writer = Log::WRITER_ELASTICSEARCH,
		                             $interv = LogElasticSearch::rotation_interval];
		Log::add_filter(stream_id, filter);
		}
	}
