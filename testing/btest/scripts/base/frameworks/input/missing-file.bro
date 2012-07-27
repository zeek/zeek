# (uses listen.bro just to ensure input sources are more reliably fully-read).
# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff bro/.stderr

@load frameworks/communication/listen

global outfile: file;
global try: count;

module A;

type Val: record {
	i: int;
	b: bool;
};

event line(description: Input::EventDescription, tpe: Input::Event, i: int, b: bool)
	{
	}

event bro_init()
	{
	try = 0;
	outfile = open("../out");
	Input::add_event([$source="does-not-exist.dat", $name="input", $fields=Val, $ev=line, $want_record=F]);
	Input::remove("input");
	}
