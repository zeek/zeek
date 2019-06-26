# @TEST-EXEC: dd if=/dev/zero of=input.log bs=8193 count=1
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out
#
# this test should be longer than one block-size. to test behavior of input-reader if it has to re-allocate stuff.

redef exit_only_after_terminate = T;

global outfile: file;
global try: count;

module A;

type Val: record {
	s: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	print outfile, tpe;
	print outfile, |s|;
	try = try + 1;
	if ( try == 1 )
		{
		Input::remove("input");
		close(outfile);
		terminate();
		}
	}

event zeek_init()
	{
	try = 0;
	outfile = open("../out");
	Input::add_event([$source="../input.log", $reader=Input::READER_RAW, $mode=Input::STREAM, $name="input", $fields=Val, $ev=line, $want_record=F]);
	}
