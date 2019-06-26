# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;
redef InputConfig::empty_field = "EMPTY";

@TEST-START-FILE configfile
testbool F    
testcount    1   
testint		-1   
testportandproto  45/udp 
testaddr 127.0.0.3 
test_set 127.0.0.1,    127.0.0.2,  127.0.0.3 
test_vector 10.0.0.1/32,  10.0.0.1/16,  10.0.0.1/8
@TEST-END-FILE

@load base/protocols/ssh
@load base/protocols/conn

global outfile: file;

export {
	option testbool: bool = T;
	option testcount: count = 0;
	option testint: int = 0;
	option testportandproto = 42/tcp;
	option testaddr = 127.0.0.1;
	option test_set: set[addr] = {};
	option test_vector: vector of subnet = {};
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

