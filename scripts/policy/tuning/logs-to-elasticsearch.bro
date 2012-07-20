##! Load this script to enable global log output to an ElasticSearch database.

module LogElasticSearch;

export {
	## An elasticsearch specific rotation interval.
	const rotation_interval = 24hr &redef;

	## Optionally ignore any :bro:enum:`Log::ID` from being sent to
	## ElasticSearch with this script.
	const excluded_log_ids: set[string] = set("Communication::LOG") &redef;

	## If you want to explicitly only send certain :bro:enum:`Log::ID` 
	## streams, add them to this set.  If the set remains empty, all will 
	## be sent.  The :bro:id:`excluded_log_ids` option will remain in 
	## effect as well.
	const send_logs: set[string] = set() &redef;
}

module Log;

event bro_init() &priority=-5
	{
	local my_filters: table[ID, string] of Filter = table();

	for ( [id, name] in filters )
		{
		local filter = filters[id, name];
		if ( fmt("%s", id) in LogElasticSearch::excluded_log_ids ||
		     (|LogElasticSearch::send_logs| > 0 && fmt("%s", id) !in LogElasticSearch::send_logs) )
			next;

		filter$name = cat(name, "-es");
		filter$writer = Log::WRITER_ELASTICSEARCH;
		filter$interv = LogElasticSearch::rotation_interval;
		my_filters[id, name] = filter;
		}

	# This had to be done separately to avoid an ever growing filters list
	# where the for loop would never end.
	for ( [id, name] in my_filters )
		{
		Log::add_filter(id, filter);
		}
	}