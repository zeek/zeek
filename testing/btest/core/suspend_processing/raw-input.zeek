# @TEST-DOC: suspend_processing() in zeek_init()
# @TEST-EXEC: echo "first line" > raw_file
# @TEST-EXEC: zeek -b -C -r $TRACES/wikipedia.trace %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

type OneLine: record {
	s: string;
};

event one_line(desc: Input::EventDescription, e: Input::Event, s: string)
	{
	print network_time(), "one_line", s;
	continue_processing();
	}

event Input::end_of_data(name: string, source: string)
	{
	print network_time(), "end_of_data", name, source;
	}

event zeek_init()
	{
	print network_time(), "zeek_init";
	suspend_processing();

	Input::add_event([
		$name="raw-read",
		# Can not use a raw command here because input reading is done
		# using heartbeats and those are working based off of network
		# time instead of either realtime or actually propagating back
		# to the main-loop when there's data ready for reading.
		#
		# IMO that's a bug in how things are implemented with the
		# readers being poll/heartbeat based. If polling based, seems
		# wallclock time would've been the better choice.
		#
		# A file works, because the first DoUpdate() does the job.
		#
		# $source="sleep 1 |",
		$source="./raw_file",
		$reader=Input::READER_RAW,
		$mode=Input::STREAM,
		$fields=OneLine,
		$ev=one_line,
		$want_record=F,
	]);
	}

event network_time_init()
	{
	print network_time(), "network_time_init";
	}

event Pcap::file_done(path: string)
	{
	print network_time(), "Pcap::file_done", path;
	}

event zeek_done()
	{
	print network_time(), "zeek_done";
	}
