# @TEST-DOC: checks for type-checking for add/delete expressions
#
# @TEST-EXEC-FAIL: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

global my_set: set[count];

event zeek_init()
	{
	local my_any1: any = add my_set[3];
	local my_any2: any = delete my_set[5];
	print my_any1, my_any2;
	}
