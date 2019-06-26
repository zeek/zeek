# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff zeek/.stderr

redef exit_only_after_terminate = T;
redef InputAscii::fail_on_file_problem = T;

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

event zeek_init()
	{
	try = 0;
	outfile = open("../out");
	Input::add_event([$source="does-not-exist.dat", $name="input", $fields=Val, $ev=line, $want_record=F]);
	}
