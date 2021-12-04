# @TEST-EXEC: zeek -b -O ZAM --optimize-files='opt-files' %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests that we can selectively pick this file.

event zeek_init()
	{
	print zeek_init;
	}
