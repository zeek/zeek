# @TEST-EXEC: btest-bg-run bro bro -b %INPUT 
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;

module A;

type Val: record {
	s: string;
	is_stderr: bool;
};

global try: count;
global outfile: file;

event line(description: Input::EventDescription, tpe: Input::Event, s: string, is_stderr: bool)
	{
	print outfile, description;
	print outfile, tpe;
	print outfile, s;
	print outfile, is_stderr;

	try = try + 1;
	if ( try == 7 )
		{
		print outfile, "done";
		close(outfile);
		Input::remove("input");
		terminate();
		}
	}

event bro_init()
	{

	local config_strings: table[string] of string = {
		["read_stderr"] = "1"
	};

	outfile = open("../out");
	try = 0;
	Input::add_event([$source="ls .. ../nonexistant ../nonexistant2 ../nonexistant3 |", $reader=Input::READER_RAW, $name="input", $fields=Val, $ev=line, $want_record=F, $config=config_strings]);
	}
