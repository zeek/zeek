# @TEST-DOC: Regression test for ZAM optimizer crashing on self-assignments.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

function my_func(n: count)
	{
	# Test direct self-assignments ...
	local self = n;
	self = self;
	print self;

	# ... and indirect ones.
	local self2 = 5;
	self = self2;
	print self;
	}

event zeek_init()
	{
	print "I didn't crash";
	}
