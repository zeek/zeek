#
# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff-remove-abspath output

event zeek_init()
	{
	print TESTFAILURE;
	}
