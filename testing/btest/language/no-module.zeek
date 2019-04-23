# @TEST-EXEC: zeek -b %INPUT secondtestfile >out
# @TEST-EXEC: btest-diff out

# This is the same test as "module.bro", but here we omit the module definition


global num: count = 123;

const daysperyear: count = 365;

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

event testevent(msg: string)
        {
	test_case( "event", T );
        }


# @TEST-START-FILE secondtestfile

# In this script, we try to access each object defined in the other script

event zeek_init()
{
	test_case( "function", T );
	test_case( "global variable", num == 123 );
	test_case( "fully qualified global variable", GLOBAL::num == 123 ); # test for BIT-1758 : GLOBAL scope ID discovery bug
	test_case( "const", daysperyear == 365 );
	event testevent( "foo" );
}

# @TEST-END-FILE
