#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local link_test = "https://www.zeek.org";
	local one_side = "abcdcab";
	local strange_chars = "dogå";

	print fmt("%s", rstrip(link_test, "org."));
	print fmt("%s", rstrip(one_side, "abc"));
	print fmt("%s", rstrip("", "å"));
	print fmt("%s", rstrip(link_test, ""));
	print fmt("%s", rstrip(strange_chars, "å"));
	print fmt("*%s*", rstrip("aaa", "a"));
	print fmt("*%s*", rstrip("   testing   \n"));
	}
