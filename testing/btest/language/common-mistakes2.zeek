# A companion tonguage/common-mistakes.zeek.  Split off because we skip this
# test when using ZAM, since it employs a type-checking violation via
# vector-of-any, which doesn't seem worth going out of our way to support
# in ZAM (and it isn't dead simple to do so).

# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"

# @TEST-EXEC: zeek -b 3.zeek >3.out 2>3.err
# @TEST-EXEC: btest-diff 3.out
# @TEST-EXEC: btest-diff 3.err

@TEST-START-FILE 3.zeek
function foo(v: vector of any)
	{
	print "in foo";
	# Vector append incompatible element type
	v += "ok";
	# Unreachable
	print "foo done";
	}

event zeek_init()
	{
	local v: vector of count;
	v += 1;
	foo(v);
	# Unreachable
	print "zeek_init done", v;
	}
@TEST-END-FILE
