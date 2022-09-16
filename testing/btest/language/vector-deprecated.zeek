# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

event zeek_init()
{
	local v6 = vector( 10, 20, 30 );
	local v16 = v6;
	v16 += 40;

	local vs1 = vector( "foo", "bar" );

	local vss2 = vs1 + "@";
	test_case( "+ operator [string]", vss2[0] == "foo@" && vss2[1] == "bar@" );

	local vss4 = (vs1 == "bar");
	test_case( "== operator [string]", vss4[0] == F && vss4[1] == T );

	local vss5 = ("bar" == vs1);
	test_case( "== operator [string]", vss5[0] == F && vss5[1] == T );
		# !=, <, >, <=, >= are handled the same as ==, skipping tests
}
