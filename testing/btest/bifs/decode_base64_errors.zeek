# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local r1 = decode_base64("^#@!@##$!===");
	print |r1| > 0 ? "FAIL" : "PASS";

	local r2 = decode_base64("\xed\xee\xef===");
	print |r2| > 0 ? "FAIL" : "PASS";
	}
