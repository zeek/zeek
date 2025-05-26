# @TEST-DOC: Check current_event_time() produces the same as event metadata, or else -1.0
#
# @TEST-EXEC: zeek -r $TRACES/http/get.trace %INPUT EventMetadata::add_network_timestamp=T > with_ts.out
# @TEST-EXEC: zeek -r $TRACES/http/get.trace %INPUT EventMetadata::add_network_timestamp=F > without_ts.out
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff with_ts.out
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff without_ts.out
# @TEST-EXEC: btest-diff .stderr


event new_connection(c: connection)
	{
	print fmt("new_connection %s current_event_time=%s network_timestamp=%s",
	          c$uid,
	          current_event_time(),
	          EventMetadata::current(EventMetadata::NETWORK_TIMESTAMP));
	}
