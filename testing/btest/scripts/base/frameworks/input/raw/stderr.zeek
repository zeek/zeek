# @TEST-EXEC: mkdir mydir && touch mydir/a && touch mydir/b && touch mydir/c
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT 
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;

type Val: record {
	s: string;
	is_stderr: bool;
};

global try = 0;
global n = 0;
global outfile: file;

event line(description: Input::EventDescription, tpe: Input::Event, s: string, is_stderr: bool)
	{
	local line_output = fmt("%s line output (stderr=%s): ", tpe, is_stderr);

	if ( is_stderr ) 
		{
		# work around localized error messages. and if some localization does not include the filename... well... that would be bad :)
		if ( strstr(s, "nonexistent") > 0 ) 
			line_output += "<stderr output contained nonexistent>";
		else
			line_output += "<unexpected/weird error localization>";
		}
	else
		line_output += s;

	print outfile, line_output;
	++try;

	if ( n == 2 && try == 7 )
		terminate();
	}

event Input::end_of_data(name: string, source:string)
	{
	print outfile, "End of Data event", name;
	++n;

	if ( n == 2 && try == 7 )
		terminate();
	}

event InputRaw::process_finished(name: string, source:string, exit_code:count, signal_exit:bool)
	{
	print outfile, "Process finished event", name, exit_code != 0;
	++n;

	if ( n == 2 && try == 7 )
		terminate();
	}

event zeek_init()
	{
	local config_strings: table[string] of string = {
		["read_stderr"] = "1"
	};

	outfile = open("../out");
	Input::add_event([$source="ls ../mydir ../nonexistent ../nonexistent2 ../nonexistent3 |",
	                 $reader=Input::READER_RAW, $name="input",
	                 $fields=Val, $ev=line, $want_record=F,
	                 $config=config_strings, $mode=Input::STREAM]);
	}
