# @TEST-EXEC: zeek -b -O ZAM --optimize-files='packet-protocols' --optimize-files='opt-files3' %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests that we can selectively pick a group of files *and* this one.

event zeek_init()
	{
	print zeek_init;
	}
