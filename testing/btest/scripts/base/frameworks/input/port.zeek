# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#fields	i	p	t
1.2.3.4	80	tcp
1.2.3.5	52	udp
1.2.3.6	30	unknown
@TEST-END-FILE

redef exit_only_after_terminate = T;

global outfile: file;

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	i: addr;
};

type Val: record {
	p: port &type_column="t";
};

global servers: table[addr] of Val = table();

event zeek_init()
	{
	outfile = open("../out");
	Input::add_table([$source="../input.log", $name="input", $idx=Idx, $val=Val, $destination=servers]);
	if ( 1.2.3.4 in servers )
		print outfile, servers[1.2.3.4];
	if ( 1.2.3.5 in servers )
		print outfile, servers[1.2.3.5];
	if ( 1.2.3.6 in servers )
		print outfile, servers[1.2.3.6];
	}

event Input::end_of_data(name: string, source: string)
	{
	print outfile, servers[1.2.3.4];
	print outfile, servers[1.2.3.5];
	print outfile, servers[1.2.3.6];
	Input::remove("input");
	close(outfile);
	terminate();
	}
