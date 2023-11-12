# @TEST-DOC: Test bad signature of callback function.

# @TEST-EXEC-FAIL: zeek  -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load base/protocols/conn

# PostDelayCallback needs to return a bool
function post_delay_cb(rec: Conn::Info, id: Log::ID)
	{
	print "post_delay_cb";
	}

hook Log::log_stream_policy(rec: Conn::Info, id: Log::ID)
	{
	Log::delay(id, rec, post_delay_cb);
	}


# @TEST-START-NEXT
@load base/protocols/conn

# PostDelayCallback needs to return a bool
function post_delay_cb(rec: Conn::Info, id: Log::ID): count
	{
	print "post_delay_cb";
	return 1;
	}

hook Log::log_stream_policy(rec: Conn::Info, id: Log::ID)
	{
	Log::delay(id, rec, post_delay_cb);
	}
