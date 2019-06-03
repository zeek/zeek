# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
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

redef exit_only_after_terminate = T;

global outfile: file;
global try: count;

redef InputAscii::empty_field = "EMPTY";

type Idx: record {
	i: int;
};

type Val: record {
	b: bool;
};

global destination: table[int] of bool = table();

event line(description: Input::TableDescription, tpe: Input::Event, left: Idx, right: bool)
	{
	print outfile, tpe;
	print outfile, left;
	print outfile, right;
	try = try + 1;
	if ( try == 7 )
		{
		Input::remove("input");
		close(outfile);
		terminate();
		}
	}

event zeek_init()
	{
	try = 0;
	outfile = open("../out");
	Input::add_table([$source="../input.log", $name="input", $idx=Idx, $val=Val, $destination=destination, $want_record=F, $ev=line]);
	}
