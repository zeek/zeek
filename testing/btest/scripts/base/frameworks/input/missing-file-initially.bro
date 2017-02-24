# This tests files that don't exist initially and then do later during
# runtime to make sure the ascii reader is resilient to files missing.
# It does a second test at the same time which configures the old 
# failing behavior.

# @TEST-EXEC: btest-bg-run bro bro %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff bro/.stdout
# @TEST-EXEC: btest-diff bro/.stderr

@TEST-START-FILE does-exist.dat
#separator \x09
#fields	line
#types	string
now it does
and more!
@TEST-END-FILE

redef exit_only_after_terminate = T;

@load base/frameworks/input

module A;

type Val: record {
	line: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, v: Val)
	{
	print v$line;
	}

event line2(description: Input::EventDescription, tpe: Input::Event, v: Val)
	{
	print "DONT PRINT THIS LINE";
	}


event bro_init()
	{
	Input::add_event([$source="../does-not-exist.dat", $name="input", $reader=Input::READER_ASCII, $mode=Input::REREAD, $fields=Val, $ev=line, $want_record=T]);
	Input::add_event([$source="../does-not-exist.dat", $name="input2", $reader=Input::READER_ASCII, $mode=Input::REREAD, $fields=Val, $ev=line2, $want_record=T, 
	                  $config=table(["fail_on_file_problem"] = "T")]);

	system("sleep 2; mv ../does-exist.dat ../does-not-exist.dat;");
	}
