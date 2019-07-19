# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global bar: function(s: string);

function bar(c: count)
	{ print "bar count", c; }

function indirect_no_impl_yet(): function(s: string)
	{ return bar; }

# function bar(s: string)
# 	{ print "bar string", s; }

event zeek_init() &priority=10
	{
	indirect_no_impl_yet()("testing");
	print "THIS SHOULD NOT BE PRINTED";
	}

event zeek_init()
	{
	print "other stuff still happens";
	}
