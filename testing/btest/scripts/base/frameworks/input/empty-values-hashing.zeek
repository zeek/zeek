# @TEST-EXEC: mv input1.log input.log
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got1 5 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: mv input2.log input.log
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input1.log
#separator \x09
#fields	i	s	ss
#types	int	sting	string
1	-	TEST
2	-	-
@TEST-END-FILE
@TEST-START-FILE input2.log
#separator \x09
#fields	i	s	ss
#types	int	sting	string
1	TEST	-
2	TEST	TEST
@TEST-END-FILE

redef exit_only_after_terminate = T;

module A;

type Idx: record {
	i: int;
};

type Val: record {
	s: string;
	ss: string;
};

global servers: table[int] of Val = table();

global outfile: file;

global try: count;

event line(description: Input::TableDescription, tpe: Input::Event, left: Idx, right: Val)
	{
	print outfile, "============EVENT============";
	print outfile, "Description";
	print outfile, description;
	print outfile, "Type";
	print outfile, tpe;
	print outfile, "Left";
	print outfile, left;
	print outfile, "Right";
	print outfile, right;
	}

event zeek_init()
	{
	outfile = open("../out");
	try = 0;
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $mode=Input::REREAD, $name="ssh", $idx=Idx, $val=Val, $destination=servers, $ev=line,
	$pred(typ: Input::Event, left: Idx, right: Val) = { 
	print outfile, "============PREDICATE============";
	print outfile, typ;
	print outfile, left;
	print outfile, right;
	return T;
	}
	]);
	}


event Input::end_of_data(name: string, source: string)
	{
	print outfile, "==========SERVERS============";
	print outfile, servers;
	
	try = try + 1;
	if ( try == 1 )
		system("touch got1");
	else if ( try == 2 )
		{
		print outfile, "done";
		close(outfile);
		Input::remove("input");
		terminate();
		}
	}
