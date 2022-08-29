# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print "Justification (input string 'abc')";
	print "----------------------------------";
	local s1 : string = "abc";
	print fmt("ljust: '%s'", ljust(s1, 2, " "));   # 'abc'
	print fmt("ljust: '%s'", ljust(s1, 3, " "));   # 'abc'
	print fmt("ljust: '%s'", ljust(s1, 5));        # 'abc  '
	print fmt("ljust: '%s'", ljust(s1, 5, "-"));   # 'abc--'
	print fmt("rjust: '%s'", rjust(s1, 2, " "));   # 'abc'
	print fmt("rjust: '%s'", rjust(s1, 3, " "));   # 'abc'
	print fmt("rjust: '%s'", rjust(s1, 5));        # '  abc'
	print fmt("rjust: '%s'", rjust(s1, 5, "-"));   # '--abc'
	print fmt("zfill: '%s'", zfill(s1, 2));        # 'abc'
	print fmt("zfill: '%s'", zfill(s1, 3));        # 'abc'
	print fmt("zfill: '%s'", zfill(s1, 5));        # '00abc'
	print "";

	print "Content checking";
	print "----------------";
	print fmt("is_num abc   : %d", is_num("abc"));
	print fmt("is_num 123   : %d", is_num("123"));
	print fmt("is_num ''    : %d", is_num(""));
	print fmt("is_alpha ab  : %d", is_alpha("ab"));
	print fmt("is_alpha 1a  : %d", is_alpha("1a"));
	print fmt("is_alpha a1  : %d", is_alpha("a1"));
	print fmt("is_alpha ''  : %d", is_alpha(""));
	print fmt("is_alnum ab  : %d", is_alnum("ab"));
	print fmt("is_alnum 1a  : %d", is_alnum("1a"));
	print fmt("is_alnum a1  : %d", is_alnum("a1"));
	print fmt("is_alnum 12  : %d", is_alnum("12"));
	print fmt("is_alnum ##12: %d", is_alnum("##12"));
	print fmt("is_alnum ''  : %d", is_alnum(""));
	print "";

	print "String counting (input str 'aabbaa')";
	print "------------------------------------";
	local s2 : string = "aabbaa";
	print fmt("count_substr aa: %d", count_substr(s2, "aa"));
	print fmt("count_substr bb: %d", count_substr(s2, "bb"));
	print fmt("count_substr cc: %d", count_substr(s2, "cc"));
	print "";

	print "Starts/endswith";
	print "---------------";
	local s3: string = "abcdefghi";
	print fmt("starts_with bro: %d", starts_with(s3, "abc"));
	print fmt("starts_with ids: %d", starts_with(s3, "ghi"));
	print fmt("ends_with ids: %d", ends_with(s3, "ghi"));
	print fmt("ends_with bro: %d", ends_with(s3, "abc"));
	print "";

	print "Transformations";
	print "---------------";
	print fmt("swap_case 'aBc': %s", swap_case("aBc"));
	print fmt("to_title 'bro is a very neat ids': '%s'", to_title("bro is a very neat ids"));
	print fmt("to_title '   ': '%s'", to_title("   "));
	print fmt("to_title '  a   c  ': '%s'", to_title("  a   c  "));
	print fmt("remove_prefix 'ananab'/'an' : %s", remove_prefix("ananab", "an"));
	print fmt("remove_prefix 'anatnab'/'an': %s", remove_prefix("anatnab", "an"));
	print fmt("remove_suffix 'banana'/'na' : %s", remove_suffix("banana", "na"));
	print fmt("remove_suffix 'bantana'/'na': %s", remove_suffix("bantana", "na"));
	print "";

	print fmt("find_str/rfind_str (input string '%s')", s3);
	print "-----------------------------------------------------";
	print fmt("find_str: %d", find_str(s3, "abcd"));
	print fmt("find_str: %d", find_str(s3, "abcd", 1));
	print fmt("find_str: %d", find_str(s3, "abcd", 0, 2));
	print fmt("find_str: %d", find_str(s3, "efg"));
	print fmt("find_str: %d", find_str(s3, "efg", 2, 6));
	print fmt("find_str: %d", rfind_str(s3, "abcd"));
	print fmt("find_str: %d", rfind_str(s3, "abcd", 1));
	print fmt("find_str: %d", rfind_str(s3, "abcd", 0, 2));
	print fmt("find_str: %d", rfind_str(s3, "efg"));
	print fmt("find_str: %d", rfind_str(s3, "efg", 2, 6));
	print "";

	print fmt("string_cat");
	print "-----------------------------------------------------";
	print fmt("string_cat: %s", string_cat("a", "b", "c"));
	}
