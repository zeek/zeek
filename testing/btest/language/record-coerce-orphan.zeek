# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type myrec: record {
	a: string;
	b: count;
	c: interval &optional;
};

function myfunc(rec: myrec)
	{
	print rec;
	}

event zeek_init()
	{
	# Orphaned fields in a record coercion reflect a programming error, like a typo, so should
	# be reported at parse-time to prevent unexpected run-time behavior.
	local rec: myrec = [$a="test", $b=42, $wtf=1sec];
	print rec;
	myfunc([$a="test", $b=42, $wtf=1sec]);
	}
