# (uses listen.bro just to ensure input sources are more reliably fully-read).
# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	b	i	
#types	bool	int
T	-42	
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

global servers: table[int] of Val = table();

event bro_init()
	{
	outfile = open("../out");
	Input::add_table([$name="input", $source="../input.log", $idx=Idx, $val=Val, $destination=servers]);
	Input::remove("input");
	}

event Input::update_finished(name: string, source: string)
	{
	print outfile, servers;
	close(outfile);
	terminate();
	}

