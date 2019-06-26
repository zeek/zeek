# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff zeek/config.log

@load base/frameworks/config
@load base/protocols/conn

redef exit_only_after_terminate = T;
redef InputConfig::empty_field = "(empty)";

@TEST-START-FILE configfile
testbool F
testcount    1
testcount 2
testcount 2
testint		-1
testenum Conn::LOG
testport 45
testaddr 127.0.0.1
testaddr 2607:f8b0:4005:801::200e
testinterval 60
testtime 1507321987
test_set a,b,c,d,erdbeerschnitzel
test_vector 1,2,3,4,5,6
test_set (empty)
test_set -
@TEST-END-FILE

@load base/protocols/ssh
@load base/protocols/conn

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
}

event Input::end_of_data(name: string, source:string)
	{
	if ( sub_bytes(name, 1,  7) != "config-" )
		return;

	terminate();
	}

event zeek_init()
	{
	Config::read_config("../configfile");
	}
