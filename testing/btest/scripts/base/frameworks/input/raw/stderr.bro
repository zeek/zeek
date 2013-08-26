# @TEST-EXEC: btest-bg-run bro bro -b %INPUT 
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;
@load base/frameworks/communication  # let network-time run. otherwise there are no heartbeats...

type Val: record {
	s: string;
	is_stderr: bool;
};

global try: count;
global outfile: file;

event line(description: Input::EventDescription, tpe: Input::Event, s: string, is_stderr: bool)
	{
	print outfile, tpe;
	if ( is_stderr ) 
		{
		# work around localized error messages. and if some localization does not include the filename... well... that would be bad :)
		if ( strstr(s, "nonexistant") > 0 ) 
			{
			print outfile, "stderr output contained nonexistant";
			}
		}
	else
		{
		print outfile, s;
		}
	print outfile, is_stderr;

	try = try + 1;
	if ( try == 7 )
		{
		print outfile, "done";
		Input::remove("input");
		}
	}

global n = 0;

event Input::end_of_data(name: string, source:string)
	{
	print outfile, "End of Data event";
	print outfile, name;
	++n;
	if ( n == 2 )
		terminate();
	}

event InputRaw::process_finished(name: string, source:string, exit_code:count, signal_exit:bool)
	{
	print outfile, "Process finished event";
	print outfile, name;
	if ( exit_code != 0 ) 
		print outfile, "Exit code != 0";
	++n;
	if ( n == 2 )
		terminate();
	}

event bro_init()
	{

	local config_strings: table[string] of string = {
		["read_stderr"] = "1"
	};

	outfile = open("../out");
	try = 0;
	Input::add_event([$source="ls .. ../nonexistant ../nonexistant2 ../nonexistant3 |", $reader=Input::READER_RAW, $name="input", $fields=Val, $ev=line, $want_record=F, $config=config_strings, $mode=Input::STREAM]);
	}
