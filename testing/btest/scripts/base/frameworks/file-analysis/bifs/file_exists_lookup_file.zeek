# @TEST-EXEC: zeek -r $TRACES/http/get.trace %INPUT 2>&1
# @TEST-EXEC: btest-diff .stdout

event zeek_init()
	{
	print "This should fail but not crash";
	print Files::lookup_file("asdf");

	print "This should return F";
	print Files::file_exists("asdf");
	}

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	print "lookup fid: " + f$id;
	local looked_up_file = Files::lookup_file(f$id);
	print "We should have found the file id: " + looked_up_file$id ;

	print "This should return T";
	print Files::file_exists(f$id);
	}
