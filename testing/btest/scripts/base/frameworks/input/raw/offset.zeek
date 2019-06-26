# @TEST-EXEC: cp input.log input2.log
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got2 5 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: echo "hi" >> input2.log
# @TEST-EXEC: btest-bg-wait 10
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
		system("touch got2");
	else if ( try == 3 )
		{
		close(outfile);
		terminate();
		}
	}

event zeek_init()
	{
	try = 0;
	outfile = open("../out");
	local config_strings: table[string] of string = {
		 ["offset"] = "2",
	};
	local config_strings_two: table[string] of string = {
		 ["offset"] = "-3", # 2 characters before end, last char is newline.
	};
	local config_strings_three: table[string] of string = {
		 ["offset"] = "-1", # End of file
	};

	Input::add_event([$source="../input.log", $config=config_strings, $reader=Input::READER_RAW, $mode=Input::STREAM, $name="input", $fields=Val, $ev=line, $want_record=F]);
	Input::add_event([$source="../input.log", $config=config_strings_two, $reader=Input::READER_RAW, $mode=Input::STREAM, $name="input2", $fields=Val, $ev=line, $want_record=F]);
	Input::add_event([$source="../input2.log", $config=config_strings_three, $reader=Input::READER_RAW, $mode=Input::STREAM, $name="input3", $fields=Val, $ev=line, $want_record=F]);
	}
