#
# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff-remove-abspath output

global a: table[count] of count;

event zeek_init()
	{
	print a[2];
	}

print a[1];

