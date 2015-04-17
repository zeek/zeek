# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: btest-bg-wait 5
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff out

@TEST-START-FILE input.log
sdfkh:KH;fdkncv;ISEUp34:Fkdj;YVpIODhfDF
@TEST-END-FILE

redef exit_only_after_terminate = T;

global outfile: file;
global try: count;

module A;

type Val: record {
	s: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	print outfile, s;
	try = try + 1;
	if ( try == 2 )
		{
		Input::remove("input");
		close(outfile);
		terminate();
		}
	}

event bro_init()
	{
	try = 0;
	outfile = open("../out");
	local config_strings: table[string] of string = {
		 ["offset"] = "2",
	};
	local config_strings_two: table[string] of string = {
		 ["offset"] = "-3", # 2 characters before end, last char is newline.
	};

	Input::add_event([$source="../input.log", $config=config_strings, $reader=Input::READER_RAW, $mode=Input::STREAM, $name="input", $fields=Val, $ev=line, $want_record=F]);
	Input::add_event([$source="../input.log", $config=config_strings_two, $reader=Input::READER_RAW, $mode=Input::STREAM, $name="input2", $fields=Val, $ev=line, $want_record=F]);
	}
