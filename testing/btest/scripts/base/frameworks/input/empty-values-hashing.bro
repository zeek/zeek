# (uses listen.bro just to ensure input sources are more reliably fully-read).
# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: cp input1.log input.log
# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: sleep 2
# @TEST-EXEC: cp input2.log input.log
# @TEST-EXEC: btest-bg-wait -k 5
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

@load frameworks/communication/listen


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

event bro_init()
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


event Input::update_finished(name: string, source: string)
	{
	print outfile, "==========SERVERS============";
	print outfile, servers;
	
	try = try + 1;
	if ( try == 2 )
		{
		print outfile, "done";
		close(outfile);
		Input::remove("input");
		terminate();
		}
	}
