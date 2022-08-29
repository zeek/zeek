# Don't run the test for transformed ASTs, as they'll stop early due to
# error propagation.
# @TEST-REQUIRES: test "${ZEEK_XFORM}" != "1"
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

event zeek_init()
	{
	print "Justification (input string 'abc')";
	print "----------------------------------";
	local s1 : string = "abc";
	print fmt("ljust: '%s'", ljust(s1, 2, "--"));  # This should return an error
	print fmt("rjust: '%s'", rjust(s1, 2, "--"));  # This should return an error
	print "";

	local s3: string = "abcdefghi";
	print fmt("find_str/rfind_str (input string '%s')", s3);
	print "-----------------------------------------------------";
	print fmt("find_str: %d", find_str(s3, "efg", 6, 2));
	print fmt("find_str: %d", rfind_str(s3, "efg", 6, 2));
	print "";

	print fmt("string_cat");
	print "-----------------------------------------------------";
	print fmt("string_cat: %s", string_cat("a", 1, "c"));
	}
