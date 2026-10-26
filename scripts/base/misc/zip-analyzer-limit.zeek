##! When the ZIP analyzer hits a limit (and stops forwarding data to other analyzers), it triggers
##! an event. This script reacts to the event in order to trigger the weird and mark the connection
##! with an 'X'.

event zip_analyzer_stats(c: connection, aid: count, total_in: count, total_out: count, exceeded: bool) {
	if ( exceeded )
		Reporter::limit_reached_weird("zip_inflate_output_size_exceeded", c, total_out, 0, "ZIP");
}
