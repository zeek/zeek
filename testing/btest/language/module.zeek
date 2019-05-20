# @TEST-EXEC: zeek -b %INPUT secondtestfile >out
# @TEST-EXEC: btest-diff out

# In this source file, we define a module and export some objects

module thisisatest;

export {
	global test_case: function(msg: string, expect: bool);

	global testevent: event(msg: string);

	global num: count = 123;

	const daysperyear: count = 365;
}

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

event testevent(msg: string)
        {
	test_case( "event", T );
        }


# @TEST-START-FILE secondtestfile

# In this source file, we try to access each exported object from the module

event zeek_init()
{
	thisisatest::test_case( "function", T );
	thisisatest::test_case( "global variable", thisisatest::num == 123 );
	thisisatest::test_case( "const", thisisatest::daysperyear == 365 );
	event thisisatest::testevent( "foo" );
}

# @TEST-END-FILE
