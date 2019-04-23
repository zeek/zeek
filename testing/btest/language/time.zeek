# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


event zeek_init()
{
	local t1: time = current_time();
	local t2: time = t1 + 3 sec;
	local t3: time = t2 - 10 sec;
	local t4: time = t1;
	local t5: time = double_to_time(1234567890);
	local t6 = current_time();	

	# Type inference test

	test_case( "type inference", type_name(t6) == "time" );

	# Operator tests

	test_case( "add interval", t1 < t2 );
	test_case( "subtract interval", t1 > t3 );
	test_case( "inequality", t1 != t3 );
	test_case( "equality", t1 == t4 );
	test_case( "subtract time", t2 - t1 == 3sec);
	test_case( "size operator", |t5| == 1234567890.0 );

}

