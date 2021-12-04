# @TEST-EXEC: zeek -b -O ZAM --optimize-files='packet-protocols' %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests that we can selectively pick a group of files but not this one.

event zeek_init()
	{
	print zeek_init;
	}
