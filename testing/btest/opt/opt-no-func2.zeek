# @TEST-EXEC-FAIL: zeek -b -O ZAM --optimize-files='my_func' %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# Make sure that --optimize-func anchors the regex.

function my_func2()
	{
	print "I shouldn't match!";
	}

event zeek_init()
	{
	print zeek_init;
	}
