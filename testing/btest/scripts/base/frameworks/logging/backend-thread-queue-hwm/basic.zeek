# @TEST-DOC: Log very fast and overload the backend thread queue.
#
# @TEST-EXEC: zeek -b %INPUT
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER='sed -E "s/Dropped [0-9]+ /Dropped XXX /g"' btest-diff .stdout

# Choose very small values to make the test fail rather fast.
redef Log::write_buffer_size = 3;
redef Log::backend_thread_queue_hwm = 3;
redef Log::drop_report_suppress_interval = 10msec;
redef Log::default_writer = Log::WRITER_NONE;

redef exit_only_after_terminate = T;

module Test;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log &default=1234.0 as time;
		c: count &log;
		i: count &log;
	} &log;
}

global max_runtime = 3sec;
global tick_batch = 20;
global tick_interval = 0.01msec;
global c = 0;

global start_time = current_time();

event tick()
	{
	local i = tick_batch;
	while ( i > 0 )
		{
		Log::write(LOG, Info($c=c, $i=i));
		--i;
		++c;
		}

	if ( current_time() - start_time > max_runtime )
		Reporter::fatal("timeout timeout timeout");

	schedule tick_interval { tick() };
	}

global drop_count = 0;

# Count reporter warning lines about dropped log lines via eventing.
event reporter_warning(t: time, msg: string, location: string)
	{
	if ( /Dropped/ in msg )
		{
		++drop_count;
		print drop_count, msg;
		}

	if ( drop_count == 5 )
		{
		print "saw 5 drop lines, terminating...";
		terminate();
		}
	}

event zeek_init()
	{
	Log::create_stream(Test::LOG, [$columns=Info, $path="test"]);

	event tick();
	}
