# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

global p1: pattern = /foo|bar/; 
global p2: pattern = /oob/; 
global p3: pattern = /^oob/; 
global p4 = /foo/;

event zeek_init()
{
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

	test_case( "& operator", p1 & p2 in "baroob" );
	test_case( "& operator", p2 & p1 in "baroob" );

	test_case( "| operator", p1 | p2 in "lazybarlazy" );
	test_case( "| operator", p3 | p4 in "xoob" );

	test_case( "/i pattern modifier", /fOO/i in "xFoObar" );
	test_case( "/i pattern modifier", /fOO/i == "Foo" );

	test_case( "/i double-quote escape", /"fOO"/i in "xFoObar" );
	test_case( "/i double-quote escape", /"fOO"/i in "xfOObar" );

	test_case( "case-sensitive pattern", /fOO/ in "xFoObar" );
	test_case( "case-sensitive pattern", /fOO/ == "Foo" );
	test_case( "case-sensitive pattern", /fOO/ == "fOO" );

	test_case( "/i pattern disjunction", /bar/i | /bez/ == "bez" );
	test_case( "/i pattern disjunction", /bar/i | /bez/ == "bEz" );
	test_case( "/i pattern disjunction", /bar/i | /bez/ == "bar" );
	test_case( "/i pattern disjunction", /bar/i | /bez/ == "bAr" );

	test_case( "/i pattern concatenation", /bar/i & /bez/ == "barbez" );
	test_case( "/i pattern concatenation", /bar/i & /bez/ == "barbEz" );
	test_case( "/i pattern concatenation", /BAR/i & /bez/ == "barbEz" );
	test_case( "/i pattern concatenation", /bar/i & /bez/ == "bArbez" );
	test_case( "/i pattern concatenation", /BAR/i & /bez/ == "bArbez" );
	test_case( "/i pattern concatenation", /bar/i & /bez/ == "bArbEz" );

	test_case( "/i pattern character class", /ba[0a-c99S-Z0]/i & /bEz/ == "bArbEz" );
	test_case( "/i pattern character class", /ba[0a-c99M-S0]/i & /bEz/ == "bArbEz" );

	test_case( "(?i:...) pattern construct", /foo|(?i:bar)/ in "xBAry" );
	test_case( "(?i:...) pattern construct", /foo|(?i:bar)/ in "xFOoy" );
	test_case( "(?i:...) pattern construct", /foo|(?i:bar)/ | /foo/i in "xFOoy" );

	test_case( "/s missing", /fOO.*bAR/ != "fOOab\ncdbAR");
	test_case( "/s pattern modifier", /fOO.*bAR/s == "fOOab\ncdbAR");
	test_case( "/s pattern disjunction", /b.r/s | /bez/ == "b\nr" );
	test_case( "/s pattern concatenation", /b.r/s & /bez/ == "b\nrbez" );

}
