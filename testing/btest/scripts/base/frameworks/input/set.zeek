# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff out

@TEST-START-FILE input.log
#separator \x09
#fields	ip
#types	addr
192.168.17.1
192.168.17.2
192.168.17.7
192.168.17.14
192.168.17.42
@TEST-END-FILE

redef exit_only_after_terminate = T;

global outfile: file;

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	ip: addr;
};

global servers: set[addr] = set();

event zeek_init()
	{
	outfile = open("../out");
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $name="ssh", $idx=Idx, $destination=servers]);
	}

event Input::end_of_data(name: string, source:string)
	{
	print outfile, servers;
	Input::remove("ssh");
	close(outfile);
	terminate();
	}
