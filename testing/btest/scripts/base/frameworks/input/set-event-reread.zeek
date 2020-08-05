# @TEST-EXEC: mv entries.set1 entries.set
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got1 15 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: mv entries.set2 entries.set
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got2 15 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: mv entries.set3 entries.set
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff out

@TEST-START-FILE entries.set1
#fields	s
one
two
three
@TEST-END-FILE

@TEST-START-FILE entries.set2
#fields	s
one
@TEST-END-FILE

@TEST-START-FILE entries.set3
#fields	s
one
four
@TEST-END-FILE

redef exit_only_after_terminate=T;

type Idx: record {
	s: string;
};

global entries: set[string] = set();
global event_count = 0;
global out = open("../out");

event entry_notify(description: Input::TableDescription, tpe: Input::Event,
                   left: Idx)
	{
	++event_count;
	print out, fmt("entry notification %s: %s", tpe, left);

	if ( event_count == 3 )
		system("touch got1");
	else if ( event_count == 5 )
		system("touch got2");
	else if ( event_count == 6 )
		{
		print out, "done";
		close(out);
		Input::remove("entries");
		terminate();
		}
	}

event zeek_init()
	{
	Input::add_table([$source="../entries.set",
	                  $name="entries",
	                  $idx=Idx,
	                  $destination=entries,
	                  $ev=entry_notify,
	                  $mode=Input::REREAD
	                  ]);
	}
