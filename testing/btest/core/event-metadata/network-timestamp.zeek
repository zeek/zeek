# @TEST-DOC: Check network timestamp available if opt-in.
#
# @TEST-EXEC: zeek -r $TRACES/http/get.trace %INPUT EventMetadata::add_network_timestamp=T > with_ts.out
# @TEST-EXEC: zeek -r $TRACES/http/get.trace %INPUT EventMetadata::add_network_timestamp=F > without_ts.out
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff with_ts.out
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff without_ts.out
# @TEST-EXEC: btest-diff .stderr


event new_connection(c: connection)
	{
	print fmt("new_connection %s all=%s network_timestamp=%s",
	          c$uid,
	          EventMetadata::current_all(),
	          EventMetadata::current(EventMetadata::NETWORK_TIMESTAMP));
	}
