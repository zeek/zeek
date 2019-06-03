# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

# In this script, we try to access each object defined in a "@load"ed script

@load secondtestfile

event zeek_init()
{
	test_case( "function", T );
	test_case( "global variable", num == 123 );
	test_case( "const", daysperyear == 365 );
	event testevent( "foo" );
}


# @TEST-START-FILE secondtestfile

# In this script, we define some objects to be used in another script

# Note: this script is not listed on the zeek command-line (instead, it
# is "@load"ed from the other script)

global test_case: function(msg: string, expect: bool);

global testevent: event(msg: string);

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

# @TEST-END-FILE

