# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


event zeek_init()
{
	local b1: bool = T; 
	local b2: bool = F;
	local b3: bool = T;
	local b4 = T;
	local b5 = F;

	test_case( "equality operator", b1 == b3 );
	test_case( "inequality operator", b1 != b2 );
	test_case( "logical or operator", b1 || b2 );
	test_case( "logical and operator", b1 && b3 );
	test_case( "negation operator", !b2 );
	test_case( "absolute value", |b1| == 1 );
	test_case( "absolute value", |b2| == 0 );
	test_case( "type inference", type_name(b4) == "bool" );
	test_case( "type inference", type_name(b5) == "bool" );

}

