# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


event bro_init()
{
	local s1: string = "";        # empty string
	local s2: string = "x";       # no escape sequences
	local s3: string = "a\0b";    # null character
	local s4: string = "a\tb";    # tab
	local s5: string = "a\nb";    # newline
	local s6: string = "a\xffb";  # hex value
	local s7: string = "a\x00b";  # hex value (null character)
	local s8: string = "a\x0ab";  # hex value (newline character)
	local s9: string = "a\011b";  # octal value (tab character)
	local s10: string = "a\"b";   # double quote
	local s11: string = "a\\b";   # backslash
	local s12: string = s2 + s3;  # string concatenation
	local s13: string = "test";
	local s14: string = "this is a very long string" +
				"which continues on the next line" +
				"the end";
	local s15: string = "on";

	test_case( "empty string", |s1| == 0 );
	test_case( "nonempty string", |s2| == 1 );
	test_case( "string comparison", s2 > s3 );
	test_case( "string comparison", s2 >= s3 );
	test_case( "string comparison", s3 < s2 );
	test_case( "string comparison", s3 <= s2 );
	test_case( "null escape sequence", |s3| == 3 );
	test_case( "tab escape sequence", |s4| == 3 );
	test_case( "newline escape sequence", |s5| == 3 );
	test_case( "hex escape sequence", |s6| == 3 );
	test_case( "hex escape sequence", |s7| == 3 );
	test_case( "hex escape sequence", |s8| == 3 );
	test_case( "octal escape sequence", |s9| == 3 );
	test_case( "quote escape sequence", |s10| == 3 );
	test_case( "backslash escape sequence", |s11| == 3 );
	test_case( "null escape sequence", s3 == s7 );
	test_case( "newline escape sequence", s5 == s8 );
	test_case( "tab escape sequence", s4 == s9 );
	test_case( "string concatenation", |s12| == 4 );
	s13 += s2;
	test_case( "string concatenation", s13 == "testx" );
	test_case( "long string initialization", |s14| == 65 );
	test_case( "in operator", s15 in s14 );
	test_case( "!in operator", s15 !in s13 );

	# type inference
	local x = "x";
	test_case( "type inference", x == s2 );
}

