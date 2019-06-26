#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local link_test = "https://www.zeek.org";
	local one_side = "abcdcab";
	local strange_chars = "ådog";

	print lstrip(link_test, "htps:/");
	print lstrip(one_side, "abc");
	print lstrip("", "å");
	print lstrip(link_test, "");
	print lstrip(strange_chars, "å");
	print fmt("*%s*", lstrip("aaa", "a"));
	print fmt("*%s*", lstrip("\n   testing   "));
	}
