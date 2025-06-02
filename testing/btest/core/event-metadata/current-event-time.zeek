# @TEST-DOC: Check current_event_time() produces the same as event metadata, or else -1.0
#
# @TEST-EXEC: zeek -r $TRACES/http/get.trace %INPUT EventMetadata::add_network_timestamp=T >> output 2>&1
# @TEST-EXEC: zeek -r $TRACES/http/get.trace %INPUT EventMetadata::add_network_timestamp=F >> output 2>&1
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output


event new_connection(c: connection)
	{
	print fmt("new_connection add_network_timestamp=%s current_event_time=%s network_timestamp=%s",
	          EventMetadata::add_network_timestamp, current_event_time(),
	          EventMetadata::current(EventMetadata::NETWORK_TIMESTAMP));
	}
