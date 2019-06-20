# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;

@TEST-START-FILE input.log
#separator \x09
#fields	i	p
#types	count	pattern
1	/dog/
2	/cat/
3	/foo|bar/
4	/^oob/
@TEST-END-FILE

global outfile: file;

module A;

type Idx: record {
	i: int;
};

type Val: record {
	p: pattern;
};

global pats: table[int] of Val = table();

event zeek_init()
	{
	outfile = open("../out");
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $name="pats", $idx=Idx, $val=Val, $destination=pats]);
	}

event Input::end_of_data(name: string, source:string)
	{
	print outfile, (pats[3]$p in "foobar"); # T
	print outfile, (pats[4]$p in "foobar"); # F
	print outfile, (pats[3]$p == "foo"); # T
	print outfile, pats;
	Input::remove("pats");
	close(outfile);
	terminate();
	}
