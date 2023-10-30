# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

@load base/protocols/http

event zeek_init()
	{
	print "This should fail but not crash";
	# The following produces a run-time warning, "non-void function
	# returning without a value" ... but not when inlined, since then
	# there's no call to a script function occurring.  Also, for
	# scripts compiled to C++, they treat all instances of returning
	# without a value in a context where a value is needed as a
	# run-time error, not just a warning.
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
