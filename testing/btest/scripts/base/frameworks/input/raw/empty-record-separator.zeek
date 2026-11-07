# @TEST-DOC: The raw reader must reject an empty record separator. Regression test for GH-5931.
#
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff zeek/.stderr

# @TEST-START-FILE input.log
AAAA
# @TEST-END-FILE

redef exit_only_after_terminate = T;
redef InputRaw::record_separator = "";

module A;

type Val: record {
	s: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	}

event zeek_init()
	{
	Input::add_event([$source="../input.log", $reader=Input::READER_RAW, $name="input", $fields=Val, $ev=line,
					  $want_record=F]);
	}

event reporter_error(t: time, msg: string, location: string)
	{
	if ( /terminating thread/ in msg )
		terminate();
	}
