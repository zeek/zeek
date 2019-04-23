# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


event zeek_init()
{
	local s1: string = "a\ty";    # tab
	local s2: string = "a\nb";    # newline
	local s3: string = "a\"b";    # double quote
	local s4: string = "a\\b";    # backslash
	local s5: string = "a\x9y";   # 1-digit hex value (tab character)
	local s6: string = "a\x0ab";  # 2-digit hex value (newline character)
	local s7: string = "a\x22b";  # 2-digit hex value (double quote)
	local s8: string = "a\x00b";  # 2-digit hex value (null character)
	local s9: string = "a\011y";  # 3-digit octal value (tab character)
	local s10: string = "a\12b";  # 2-digit octal value (newline character)
	local s11: string = "a\0b";   # 1-digit octal value (null character)

	local s20: string = "";
	local s21: string = "x";
	local s22: string = s21 + s11;
	local s23: string = "test";
	local s24: string = "this is a very long string" +
				"which continues on the next line" +
				"the end";
	local s25: string = "on";
	local s26 = "x";

	# Type inference test

	test_case( "type inference", type_name(s26) == "string" );

	# Escape sequence tests

	test_case( "tab escape sequence", |s1| == 3 );
	test_case( "newline escape sequence", |s2| == 3 );
	test_case( "double quote escape sequence", |s3| == 3 );
	test_case( "backslash escape sequence", |s4| == 3 );
	test_case( "1-digit hex escape sequence", |s5| == 3 );
	test_case( "2-digit hex escape sequence", |s6| == 3 );
	test_case( "2-digit hex escape sequence", |s7| == 3 );
	test_case( "2-digit hex escape sequence", |s8| == 3 );
	test_case( "3-digit octal escape sequence", |s9| == 3 );
	test_case( "2-digit octal escape sequence", |s10| == 3 );
	test_case( "1-digit octal escape sequence", |s11| == 3 );
	test_case( "tab escape sequence", s1 == s5 );
	test_case( "tab escape sequence", s5 == s9 );
	test_case( "newline escape sequence", s2 == s6 );
	test_case( "newline escape sequence", s6 == s10 );
	test_case( "double quote escape sequence", s3 == s7 );
	test_case( "null escape sequence", s8 == s11 );

	# Operator tests

	test_case( "empty string", |s20| == 0 );
	test_case( "nonempty string", |s21| == 1 );
	test_case( "string comparison", s21 > s11 );
	test_case( "string comparison", s21 >= s11 );
	test_case( "string comparison", s11 < s21 );
	test_case( "string comparison", s11 <= s21 );
	test_case( "string concatenation", |s22| == 4 );
	s23 += s21;
	test_case( "string concatenation", s23 == "testx" );
	test_case( "multi-line string initialization", |s24| == 65 );
	test_case( "in operator", s25 in s24 );
	test_case( "!in operator", s25 !in s23 );

}

