# This tests files that don't exist initially and then do later during
# runtime to make sure the ascii reader is resilient to files missing.
# It does a second test at the same time which configures the old
# failing behavior.

# @TEST-EXEC: btest-bg-run bro bro %INPUT
# @TEST-EXEC: sleep 10
# @TEST-EXEC: mv does-exist.dat does-not-exist.dat
# @TEST-EXEC: sleep 2
# @TEST-EXEC: mv does-not-exist.dat does-not-exist-again.dat
# @TEST-EXEC: echo "3 streaming still works" >> does-not-exist-again.dat
# @TEST-EXEC: btest-bg-wait -k 3
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff bro/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff bro/.stderr

@TEST-START-FILE does-exist.dat
#separator \x09
#fields	line
#types	string
1 now it does
2 and more!
@TEST-END-FILE

redef exit_only_after_terminate = T;

@load base/frameworks/input

module A;

type Val: record {
	line: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, v: Val)
	{
	print fmt("%s: %s", description$name, v$line);
	}

event line2(description: Input::EventDescription, tpe: Input::Event, v: Val)
	{
	print "DONT PRINT THIS LINE";
	}


event bro_init()
	{
	Input::add_event([$source="../does-not-exist.dat", $name="input", $reader=Input::READER_ASCII, $mode=Input::REREAD, $fields=Val, $ev=line, $want_record=T]);
	Input::add_event([$source="../does-not-exist.dat", $name="inputstream", $reader=Input::READER_ASCII, $mode=Input::STREAM, $fields=Val, $ev=line, $want_record=T]);
	Input::add_event([$source="../does-not-exist.dat", $name="inputmanual", $reader=Input::READER_ASCII, $mode=Input::MANUAL, $fields=Val, $ev=line, $want_record=T]);
	Input::add_event([$source="../does-not-exist.dat", $name="input2", $reader=Input::READER_ASCII, $mode=Input::REREAD, $fields=Val, $ev=line2, $want_record=T,
	                  $config=table(["fail_on_file_problem"] = "T")]);
	}
