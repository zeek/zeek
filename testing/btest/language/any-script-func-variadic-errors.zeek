# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

function f(x: any)
	{
	local l = "a local";
	print fmt("l=%s x=%s", l, x);
	}

event zeek_init() &priority=10
	{
	print "zeek_init() &priority=10";
	f(1);
	f(1, 2);
	# Not reached
	print "FAIL";
	f(1);
	}

event zeek_init() &priority=-10
	{
	print "zeek_init() &priority=-10";
	f(1);
	f(1);
	}


@TEST-START-NEXT
# Do not allow to call variadic through a script-level variable.
global f: function(x: any);

event zeek_init()
	{
	local _lambda = function(x: any) {
		local l = "lambda local";
		print fmt("l=%s x=%s", l, x);
	};

	f = _lambda;

	f(1);
	f(1, 2);
	# Not reached
	print "FAIL";
	f(1);
	}
