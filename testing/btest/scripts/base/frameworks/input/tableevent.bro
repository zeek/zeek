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
global try: count;

redef InputAscii::empty_field = "EMPTY";

type Idx: record {
	i: int;
};

type Val: record {
	b: bool;
};

global destination: table[int] of Val = table();

event line(description: Input::TableDescription, tpe: Input::Event, left: Idx, right: bool)
	{
	print outfile, description;
	print outfile, tpe;
	print outfile, left;
	print outfile, right;
	try = try + 1;
	if ( try == 7 )
		{
		close(outfile);
		terminate();
		}
	}

event bro_init()
	{
	try = 0;
	outfile = open("../out");
	Input::add_table([$source="../input.log", $name="input", $idx=Idx, $val=Val, $destination=destination, $want_record=F,$ev=line]);
	Input::remove("input");
	}
