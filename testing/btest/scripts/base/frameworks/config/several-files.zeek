# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-canonifier | grep -v ^# | $SCRIPTS/diff-sort" btest-diff zeek/config.log

@load base/frameworks/config
@load base/protocols/conn

redef exit_only_after_terminate = T;
redef Config::config_files += {"../configfile1", "../configfile2"};

@TEST-START-FILE configfile1
testbool F
testcount 2
testint		-1
testenum Conn::LOG
test_set a,b,c,d,erdbeerschnitzel
test_vector 1,2,3,4,5,6
@TEST-END-FILE

@TEST-START-FILE configfile2
testport 45
testaddr 127.0.0.1
testinterval 60
testtime 1507321987
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

global ct = 0;

event Input::end_of_data(name: string, source: string)
	{
	if ( sub_bytes(name, 1, 7) != "config-" )
		return;

	++ct;

	# Exit after this event has been raised for each config file.
	if ( ct == 2 )
		terminate();

	}
