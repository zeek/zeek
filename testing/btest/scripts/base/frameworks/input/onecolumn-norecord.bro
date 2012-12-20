# @TEST-EXEC: btest-bg-run bro bro -b --pseudo-realtime -r $TRACES/socks.trace %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	b	i	
#types	bool	int
T	-42	
@TEST-END-FILE

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
	Input::add_table([$source="../input.log", $name="input", $idx=Idx, $val=Val, $destination=servers, $want_record=F]);
	Input::remove("input");
	}

event Input::end_of_data(name: string, source: string)
	{
	print outfile, servers;
	close(outfile);
	terminate();
	}

