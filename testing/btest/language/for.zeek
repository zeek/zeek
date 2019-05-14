# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }



event zeek_init()
{
	local vv: vector of string = vector( "a", "b", "c" );
	local ct: count = 0;

	# Test a "for" loop without "break" or "next"

	ct = 0;
	for ( i in vv ) ++ct;
	test_case("for loop", ct == 3 );

	# Test the "break" statement

	ct = 0;
	for ( i in vv )
	{
		++ct;
		break;
		test_case("Error: this should not happen", F);
	}
	test_case("for loop with break", ct == 1 );

	# Test the "next" statement

	ct = 0;
	for ( i in vv )
	{
		++ct;
		next;
		test_case("Error: this should not happen", F);
	}
	test_case("for loop with next", ct == 3 );

	# Test keys that are tuples

	local t: table[count, count] of string = table();
	t[1, 2] = "hi";

	local s1: string = "";

	for ( [i, j] in t )
		s1 = fmt("%d %d %s", i, j, t[i,j]);

	test_case("keys that are tuples", s1 == "1 2 hi");

	# Tests for key value for loop are in key-value-for.bro
}
