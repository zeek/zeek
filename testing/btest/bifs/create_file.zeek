#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff testfile
# @TEST-EXEC: btest-diff testfile2
# @TEST-EXEC: test -f testdir/testfile4

event zeek_init()
	{
	# Test that creating a file works as expected
	local a = open("testfile");
	print active_file(a);
	print get_file_name(a);
	write_file(a, "This is a test\n");
	close(a);

	print active_file(a);
	print file_size("testfile");

	# Test that "open_for_append" doesn't overwrite an existing file
	a = open_for_append("testfile");
	print active_file(a);
	write_file(a, "another test\n");
	close(a);

	print active_file(a);
	print file_size("testfile");

	# This should fail
	print file_size("doesnotexist");

	# Test that "open" overwrites existing file
	a = open("testfile2");
	write_file(a, "this will be overwritten\n");
	close(a);
	a = open("testfile2");
	write_file(a, "new text\n");
	close(a);

	# Test that set_buf and flush_all work correctly
	a = open("testfile3");
	set_buf(a, F);
	write_file(a, "This is a test\n");
	print file_size("testfile3");
	close(a);
	a = open("testfile3");
	set_buf(a, T);
	write_file(a, "This is a test\n");
	print file_size("testfile3");
	print flush_all();
	print file_size("testfile3");
	close(a);

	# Create a new directory
	print mkdir("testdir");

	# Create a file in the new directory
	a = open("testdir/testfile4");
	print get_file_name(a);
	write_file(a, "This is a test\n");
	close(a);

	# This should fail
	print mkdir("/thisdoesnotexist/dir");
	}
