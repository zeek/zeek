# (uses listen.bro just to ensure input sources are more reliably fully-read).
# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	i	b	
#types	int	bool
1	T
2	T
3	F
4	F
5	F
6	F
7	T
@TEST-END-FILE

@load frameworks/communication/listen

global outfile: file;

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	i: int;
};

type Val: record {
	b: bool;
};

global servers: table[int] of bool = table();

event bro_init()
	{
	outfile = open("../out");
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $name="input", $idx=Idx, $val=Val, $destination=servers, $want_record=F,
				$pred(typ: Input::Event, left: Idx, right: bool) = { return right; }
				]);
	Input::remove("input");
	}

event Input::update_finished(name: string, source: string)
	{
	if ( 1 in servers )
		print outfile, "VALID";
	if ( 2 in servers )
		print outfile, "VALID";
	if ( !(3 in servers) )
		print outfile, "VALID";
	if ( !(4 in servers) )
		print outfile, "VALID";
	if ( !(5 in servers) )
		print outfile, "VALID";
	if ( !(6 in servers) )
		print outfile, "VALID";
	if ( 7 in servers )
		print outfile, "VALID";
	close(outfile);
	terminate();
	}
