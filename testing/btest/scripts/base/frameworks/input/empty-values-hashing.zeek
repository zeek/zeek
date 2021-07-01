# @TEST-EXEC: mv input1.log input.log
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got1 15|| (btest-bg-wait -k 1 && false)
# @TEST-EXEC: mv input2.log input.log
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff servers.out
# @TEST-EXEC: btest-diff events.out
# @TEST-EXEC: btest-diff preds.out

@TEST-START-FILE input1.log
#separator \x09
#fields	i	s	ss
#types	int	sting	string
1	-	-
2	-	TEST
3	TEST	-
4	TEST	TEST
@TEST-END-FILE
@TEST-START-FILE input2.log
#separator \x09
#fields	i	s	ss
#types	int	sting	string
1	TEST2	-
4	TEST2	TEST2
5	-	TEST2
@TEST-END-FILE

redef exit_only_after_terminate = T;

module A;

type Idx: record {
	i: int;
};

type Val: record {
	s: string;
	ss: string &optional;
};

type servers_type: table[int] of Val;
global servers: servers_type = table();

global servers_file = open("../servers.out");
global events_file = open("../events.out");
global predicates_file = open("../preds.out");

global try: count;

event line(description: Input::TableDescription, tpe: Input::Event, left: Idx, right: Val)
	{
	print events_file, "============EVENT============";
	print events_file, "Description";
	print events_file, "  source", description$source;
	print events_file, "  reader", description$reader;
	print events_file, "  mode", description$mode;
	print events_file, "  name", description$name;
	print events_file, fmt("  destination[left = %s]", left$i),
	    (description$destination as servers_type)[left$i];
	print events_file, "  idx", description$idx;
	print events_file, "  val", description$val;
	print events_file, "  want_record", description$want_record;
	print events_file, "Type", tpe;
	print events_file, "Left", left;
	print events_file, "Right", right;
	}

event zeek_init()
	{
	try = 0;
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $mode=Input::REREAD, $name="ssh",
	                  $idx=Idx, $val=Val, $destination=servers, $ev=line,
	                  $pred(typ: Input::Event, left: Idx, right: Val) = {
	                      print predicates_file, "============PREDICATE============";
	                      print predicates_file, typ;
	                      print predicates_file, left;
	                      print predicates_file, right;
	                      return T;
	                      }
	]);
	}


event Input::end_of_data(name: string, source: string)
	{
	print servers_file, "==========SERVERS============";
	print servers_file, servers;

	try = try + 1;

	if ( try == 1 )
		system("touch got1");
	else if ( try == 2 )
		{
		print servers_file, "done";
		close(servers_file);
		close(events_file);
		close(predicates_file);
		Input::remove("input");
		terminate();
		}
	}
