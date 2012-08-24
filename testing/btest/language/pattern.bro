# @TEST-EXEC: bro %INPUT >out
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

	test_case( "equality operator", "foo" == p1 );
	test_case( "equality operator (order of operands)", p1 == "foo" );
	test_case( "inequality operator", "foobar" != p1 );
	test_case( "in operator", p1 in "foobar" );
	test_case( "in operator", p2 in "foobar" );
	test_case( "!in operator", p3 !in "foobar" );

	# type inference
	local x = /foo|bar/;
	local y = /foo/;
	local z = /^foo/;
}

