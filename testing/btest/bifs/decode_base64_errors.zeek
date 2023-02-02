# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep character.*ignored' btest-diff out

event zeek_init()
	{
	decode_base64("^#@!@##$!===");
	decode_base64("\xed\xee\xef===");
	}
