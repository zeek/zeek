# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	i	b	s	ss
#types	int	bool	string	string
1	T	test1	idx1
2	T	test2	idx2
@TEST-END-FILE

redef exit_only_after_terminate = T;

global outfile: file;

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	i: int;
	ss: string;
};

type Val: record {
	b: bool;
	s: string;
};

global servers: table[int, string] of Val = table();

event zeek_init()
	{
	outfile = open("../out");

	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $name="input", $idx=Idx, $val=Val, $destination=servers, 
				$pred(typ: Input::Event, left: Idx, right: Val) = { 
				if ( left$i == 1 )
					right$s = "testmodified";
				if ( left$i == 2 )
					left$ss = "idxmodified";
				return T; 
				}
				]);
	}

event Input::end_of_data(name: string, source: string)
	{
	print outfile, servers;
	Input::remove("input");
	close(outfile);
	terminate();
	}
