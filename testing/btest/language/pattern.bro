# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


event bro_init()
{
	local p1: pattern = /foo|bar/; 
	local p2: pattern = /oob/; 
	local p3: pattern = /^oob/; 
	local p4 = /foo/;

	# Type inference tests

	test_case( "type inference", type_name(p4) == "pattern" );

	# Operator tests

	test_case( "equality operator", "foo" == p1 );
	test_case( "equality operator (order of operands)", p1 == "foo" );
	test_case( "inequality operator", "foobar" != p1 );
	test_case( "inequality operator (order of operands)", p1 != "foobar" );
	test_case( "in operator", p1 in "foobar" );
	test_case( "in operator", p2 in "foobar" );
	test_case( "!in operator", p3 !in "foobar" );

}

