# Don't run for C++ script compilation, as the C++ compiler itself complains
# about the constants.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

global i1: int = 9223372036854775807;   # max. allowed value
global i2: int = -9223372036854775808;  # min. allowed value
global i3: int = 0x7fffffffffffffff;   # max. allowed value
global i4: int = -0x8000000000000000;  # min. allowed value

event zeek_init()
{
	# Max/min value tests.  We do these separately from language/int.zeek
	# because they generate compile-time errors for scripts compiled to
	# C++.

	local str1 = fmt("max int value = %d", i1);
	test_case( str1, str1 == "max int value = 9223372036854775807" );
	local str2 = fmt("min int value = %d", i2);
	test_case( str2, str2 == "min int value = -9223372036854775808" );
	local str3 = fmt("max int value = %d", i3);
	test_case( str3, str3 == "max int value = 9223372036854775807" );
	local str4 = fmt("min int value = %d", i4);
	test_case( str4, str4 == "min int value = -9223372036854775808" );
}
