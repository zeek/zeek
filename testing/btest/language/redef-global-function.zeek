# @TEST-EXEC: zeek -b %INPUT -e "redef funcb = func2;" > out
# @TEST-EXEC-FAIL: zeek -b %INPUT -e "redef funca = func2;" >> out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

export {
	global func1: function();
	global func2: function();
}

function func1()
	{
	print "func1()";
	}

function func2()
	{
	print "func2()";
	}

export {
	global funca = func1;
	global funcb = func1 &redef;
}

event zeek_init()
	{
	funcb();
	}
