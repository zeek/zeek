# (uses listen.bro just to ensure input sources are more reliably fully-read).
# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
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


@load frameworks/communication/listen

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

event bro_init()
	{
	outfile = open("../out");
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $name="ssh", $idx=Idx, $val=Val, $destination=servers]);
	Input::remove("ssh");
	}

event Input::update_finished(name: string, source:string)
	{
	print outfile, servers;
	close(outfile);
	terminate();
	}
