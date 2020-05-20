# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T; 

@TEST-START-FILE input.log
#separator \x09
#fields	i	c
#types	int	count
9223372036854775800	18446744073709551612
-9223372036854775800	18446744073709551612
@TEST-END-FILE

global outfile: file;

module A;

type Idx: record {
	i: int;
};

type Val: record {
	c: count;
};

global servers: table[int] of Val = table();

event zeek_init()
	{
	outfile = open("../out");
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $name="ssh", $idx=Idx, $val=Val, $destination=servers]);
	}

event Input::end_of_data(name: string, source:string)
	{
	print outfile, servers;
	Input::remove("ssh");
	close(outfile);
	terminate();
	}
