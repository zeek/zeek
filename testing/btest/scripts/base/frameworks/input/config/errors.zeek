# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: tail -n +2 .stderr > errout
# @TEST-EXEC: btest-diff errout

redef exit_only_after_terminate = T;

@TEST-START-FILE configfile
testbool A
testtesttesttesttesttest
testbool A B
testcount A
testenum unknown
testbooool T
test_any F
test_table whatever
@TEST-END-FILE

@load base/protocols/ssh
@load base/protocols/conn

global outfile: file;

export {
	option testbool: bool = T;
	option testcount: count = 0;
	option testint: int = 0;
	option testenum = SSH::LOG;
	option testport = 42/tcp;
	option testaddr = 127.0.0.1;
	option testtime = network_time();
	option testinterval = 1sec;
	option teststring = "a";
	option test_set: set[string] = {};
	option test_vector: vector of count = {};
	option test_any: any = 5;
	option test_table: table[string] of string = {};
}

type Idx: record {
	option_name: string;
};

type Val: record {
	option_val: string;
};

global currconfig: table[string] of string = table();

event InputConfig::new_value(name: string, source: string, id: string, value: any)
	{
	print outfile, id, value;
	}

event Input::end_of_data(name: string, source:string)
	{
	close(outfile);
	terminate();
	}

event zeek_init()
	{
	outfile = open("../out");
	Input::add_table([$reader=Input::READER_CONFIG, $source="../configfile", $name="configuration", $idx=Idx, $val=Val, $destination=currconfig, $want_record=F]);
	}

