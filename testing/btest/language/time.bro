# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


event bro_init()
{
	local t1: time = current_time();
	local t2: time = t1 + 3 sec;
	local t3: time = t2 - 10 sec;
	local t4: time = t1;
	local t5: interval = t2 - t1;

	test_case( "add interval", t1 < t2 );
	test_case( "subtract interval", t1 > t3 );
	test_case( "inequality", t1 != t3 );
	test_case( "equality", t1 == t4 );
	test_case( "subtract time", t5 == 3sec);
	test_case( "size operator", |t1| > 1.0);

	local x = current_time();	
	test_case( "type inference", x > t1 );
}

