# @TEST-DOC: The raw reader must reject InputRaw::record_separator = "" instead of hanging. Regression test for GH-5931.
#
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff zeek/.stderr

# @TEST-START-FILE input.log
AAAA
# @TEST-END-FILE

redef exit_only_after_terminate = T;
redef InputRaw::record_separator = "";

global outfile: file;

module A;

type Val: record {
	s: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	# Should never fire: an empty record_separator must be rejected at
	# Init time rather than ever producing a (zero-length) record.
	print outfile, "unexpected line event", s;
	}

event zeek_init()
	{
	outfile = open("../out");
	Input::add_event([$source="../input.log", $reader=Input::READER_RAW, $name="input", $fields=Val, $ev=line,
	                   $want_record=F]);
	}

event reporter_error(t: time, msg: string, location: string)
	{
	if ( /terminating thread/ in msg )
		terminate();
	}
