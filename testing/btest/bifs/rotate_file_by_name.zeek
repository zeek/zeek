#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = open("testfile");
	write_file(a, "this is a test\n");
	close(a);

	local b = rotate_file_by_name("testfile");
	if ( b$new_name != "testfile" )
		print "file rotated";
	print file_size(b$new_name);
	print file_size("testfile");
	}
