#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = "this is a test";
	local pat = /is|ss/;

	print sub(a, pat, "at");
	print gsub(a, pat, "at");
	}
