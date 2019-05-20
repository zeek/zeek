#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local s1 = "hello world!";
	local s2 = "rise to vote sir";
	local s3 = "\xff\x00";
	local s4 = "\xff\x39\x30\xff";

	print reverse(s1);
	print reverse(reverse(s1));
	print subst_string(reverse(s2), " ", "");
	print bytestring_to_hexstr(s3);
	print bytestring_to_hexstr(reverse(s3));
	print bytestring_to_hexstr(reverse(sub_bytes(s4, 2, 2)));
	print reverse("A");
	}
