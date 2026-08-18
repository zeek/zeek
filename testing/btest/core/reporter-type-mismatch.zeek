#
# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff-remove-abspath output

event foo(a: string)
	{
	}

event zeek_init()
	{
	event foo(42);
	}
