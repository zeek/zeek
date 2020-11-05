# @TEST-REQUIRES: test "${ZEEK_XFORM}" != "1"
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print "Justification (input string 'abc')";
	print "----------------------------------";
	local s1 : string = "abc";
	print fmt("ljust: '%s'", ljust(s1, 2, "--"));  # This should return an error
	print fmt("rjust: '%s'", rjust(s1, 2, "--"));  # This should return an error
	local s3: string = "abcdefghi";
	print fmt("find_str: %d", find_str(s3, "efg", 6, 2));
	print fmt("find_str: %d", rfind_str(s3, "efg", 6, 2));
	print "";
	}
