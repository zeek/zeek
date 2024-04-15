# A companion to language/common-mistakes.zeek.  Split off because we skip
# this test when using script optimization, since it employs a type-checking
# violation via vector-of-any, which doesn't seem worth going out of our way
# to support for script optimization.

# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"

# @TEST-EXEC: zeek -b %INPUT >out 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

function foo(v: vector of any)
	{
	print "in foo";
	# Vector append incompatible element type
	v += "ok";
	# Unreachable
	print "foo done";
	}

function bar(l: list of any)
	{
	print "in bar";
	# List append incompatible element type
	l += "ok";
	# Unreachable
	print "bar done";
	}

event zeek_init()
	{
	local v: vector of count;
	v += 1;
	foo(v);
	# Unreachable
	print "zeek_init #1 done", v;
	}

event zeek_init()
	{
	local l: list of count;
	l += 1;
	bar(l);
	# Unreachable
	print "zeek_init #2 done", l;
	}
