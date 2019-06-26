# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;
redef InputConfig::empty_field = "EMPTY";
redef InputConfig::set_separator = "\t";

@TEST-START-FILE configfile
testbool F
testcount    1
testcount 2
testcount 2
testint		-1
testenum Conn::LOG
testport 45
testportandproto 45/udp
testaddr 127.0.0.1
testaddr 2607:f8b0:4005:801::200e
testinterval 60
testtime 1507321987
test_set a	b	c	d	erdbeerschnitzel
test_vector 1	2	3	4	5	6
test_set (empty)
test_set EMPTY
test_set -
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
	option testportandproto = 42/tcp;
	option testaddr = 127.0.0.1;
	option testtime = network_time();
	option testinterval = 1sec;
	option teststring = "a";
	option test_set: set[string] = {};
	option test_vector: vector of count = {};
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

