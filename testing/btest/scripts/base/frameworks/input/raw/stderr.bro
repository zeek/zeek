# @TEST-EXEC: btest-bg-run bro bro -b %INPUT 
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;

type Val: record {
	s: string;
	is_stderr: bool;
};

global try: count;
global outfile: file;

event line(description: Input::EventDescription, tpe: Input::Event, s: string, is_stderr: bool)
	{
	print outfile, tpe;
	print outfile, s;
	print outfile, is_stderr;

	try = try + 1;
	if ( try == 7 )
		{
		print outfile, "done";
		Input::remove("input");
		}
	}

event Input::end_of_data(name: string, source:string)
	{
	print outfile, "End of Data event";
	print outfile, name;
	terminate(); # due to the current design, end_of_data will be called after process_finshed and all line events.
	# this could potentially change
	}

event InputRaw::process_finished(name: string, source:string, exit_code:count, signal_exit:bool)
	{
	print outfile, "Process finished event";
	print outfile, name;
	print outfile, exit_code;
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
