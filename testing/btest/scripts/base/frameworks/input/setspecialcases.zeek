# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff out

@TEST-START-FILE input.log
#separator \x09
#fields	i	s	ss
1	testing\x2ctesting\x2ctesting\x2c	testing\x2ctesting\x2ctesting\x2c
2	testing,,testing	testing,,testing
3	,testing	,testing
4	testing,	testing,
5	,,,	,,,
6		
@TEST-END-FILE


redef exit_only_after_terminate = T;

global outfile: file;

module A;

type Idx: record {
	i: int;
};

type Val: record {
	s: set[string];
	s: vector of string;
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
