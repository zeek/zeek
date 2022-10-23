# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff out
# @TEST-EXEC: sed 1d .stderr > .stderrwithoutfirstline
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderrwithoutfirstline

@TEST-START-FILE input.log
#separator \x09
#fields	i	s
name	-
name	127.0.0.1
@TEST-END-FILE

redef exit_only_after_terminate = T;
redef InputAscii::fail_on_invalid_lines = T;

global outfile: file;

module A;

type Idx: record {
	i: string;
};

type Val: record {
	s: set[subnet];
};

global endcount: count = 0;

global servers: table[string] of Val = table();

event handle_our_errors(desc: Input::TableDescription, msg: string, level: Reporter::Level)
	{
	print outfile, "TableErrorEvent", msg, level;
	}

event handle_our_errors_event(desc: Input::EventDescription, msg: string, level: Reporter::Level)
	{
	print outfile, "EventErrorEvent", msg, level;
	}

event line(description: Input::EventDescription, tpe: Input::Event, v: Val)
	{
	print outfile, "Event", v;
	}

event zeek_init()
	{
	outfile = open("../out");
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $name="ssh", $error_ev=handle_our_errors, $idx=Idx, $val=Val, $destination=servers]);
	}

event Input::end_of_data(name: string, source:string)
	{
	++endcount;

	# ... and when we're done, move to reading via events.
	# This makes the reads sequential, avoiding races in the output.
	if ( endcount == 1 )
		{
		Input::add_event([$source="../input.log", $name="sshevent", $error_ev=handle_our_errors_event, $fields=Val, $want_record=T, $ev=line]);
		}

	if ( endcount == 2 )
		{
		print outfile, servers;
		terminate();
		}
	}
