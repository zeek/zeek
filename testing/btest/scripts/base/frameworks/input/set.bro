# (uses listen.bro just to ensure input sources are more reliably fully-read).
# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
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

@load frameworks/communication/listen

global outfile: file;

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	ip: addr;
};

global servers: set[addr] = set();

event bro_init()
	{
	outfile = open("../out");
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $name="ssh", $idx=Idx, $destination=servers]);
	Input::remove("ssh");
	}

event Input::update_finished(name: string, source:string)
	{
	print outfile, servers;
	close(outfile);
	terminate();
	}
