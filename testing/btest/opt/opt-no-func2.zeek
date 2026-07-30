# @TEST-EXEC-FAIL: zeek -b -O ZAM --optimize-files=my_func %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr

# Make sure that --optimize-func anchors the regex.

function my_func2()
	{
	print "I shouldn't match!";
	}

event zeek_init()
	{
	print zeek_init;
	}
