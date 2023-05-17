# @TEST-DOC: The raw reader would read a file in MODE_REREAD twice initially. Check this is fixed by running with reduced heartbeat_interval and waiting for 20 intervals after the first end_of_data event.
#
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
First
Second
Third

Fourth
@TEST-END-FILE

@load base/frameworks/input

# By default the heartbeat timer is 1sec. To avoid running this test for
# multiple seconds, tune it down 100x. 10msec is still pretty long.
redef Threading::heartbeat_interval = 10msec;
redef exit_only_after_terminate = T;

module A;

type Val: record {
	s: string;
};

event do_terminate()
	{
	if ( zeek_is_terminating() )
		return;

	print "terminate";
	terminate();
	}

event Input::end_of_data(name: string, source: string)
	{
	print "end_of_data", name, source;
	schedule 20 * Threading::heartbeat_interval { do_terminate() };
	}

global lines = 0;

event A::line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	++lines;
	print "A::line", lines, s, |s|;
	}

event zeek_init()
	{
	# In case something goes wrong.
	schedule 10sec { do_terminate() };

	Input::add_event([
		$source="./input.log",
		$reader=Input::READER_RAW,
		$mode=Input::REREAD,
		$name="input",
		$fields=Val,
		$ev=A::line,
		$want_record=F,
	]);
	}
