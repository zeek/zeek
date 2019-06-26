#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	# Test succesful operations...
	print mkdir("testdir");
	print mkdir("testdir");
	local a = open("testdir/testfile");
	close(a);
	print rename("testdir/testfile", "testdir/testfile2");
	print rename("testdir", "testdir2");
	print unlink("testdir2/testfile2");
	print rmdir("testdir2");


	print unlink("nonexisting");
	print rename("a", "b");
	print rmdir("nonexisting");
	a = open("testfile");
	close(a);
	print mkdir("testfile");
	}
