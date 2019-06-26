#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = open("testfile");
	write_file(a, "this is a test\n");

	local b = rotate_file(a);
	if ( b$new_name != "testfile" )
		print "file rotated";
	print file_size(b$new_name);
	print file_size("testfile");
	}
