# @TEST-EXEC: btest-bg-run zeek "zeek -b %INPUT >output 2>&1"
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-remove-timestamps | $SCRIPTS/diff-sort" btest-diff zeek/output

# interpreter exceptions in "when" blocks shouldn't cause termination

@load base/utils/exec
redef exit_only_after_terminate = T;

type MyRecord: record {
	a: bool &default=T;
	notset: bool &optional;
};

global myrecord: MyRecord;

global c = 0;

function check_term_condition()
	{
	++c;

	#print "check_term_condition", c;

	if ( c == 6 )
		terminate();
	}

event termination_check()
	{
	#print "termination_check event";
	check_term_condition();
	}

function f(do_exception: bool): bool
	{
	local cmd = Exec::Command($cmd=fmt("echo 'f(%s)'",
	                          do_exception));

	return when ( local result = Exec::run(cmd) )
		{
		print result$stdout;

		if ( do_exception )
			{
			event termination_check();
			print myrecord$notset;
			}

		return T;
		}

	check_term_condition();
	return F;
	}

function g(do_exception: bool): bool
	{
	local stall = Exec::Command($cmd="sleep 30");

	return when ( local result = Exec::run(stall) )
		{
		print "shouldn't get here, g()", do_exception, result;
		}
	timeout 0 sec
		{
		print "timeout g()", do_exception;

		if ( do_exception )
			{
			event termination_check();
			print myrecord$notset;
			}

		return T;
		}

	check_term_condition();
	return F;
	}

event zeek_init()
	{
	local cmd = Exec::Command($cmd="echo 'zeek_init()'");
	local stall = Exec::Command($cmd="sleep 30");

	when ( local result = Exec::run(cmd) )
		{
		print result$stdout;
		event termination_check();
		print myrecord$notset;
		}

	when ( local result2 = Exec::run(stall) )
		{
		print "shouldn't get here", result2;
		check_term_condition();
		}
	timeout 0 sec
		{
		print "timeout";
		event termination_check();
		print myrecord$notset;
		}

	when ( local b = f(T) )
		print "f() exception done (shouldn't be printed)", b;

	when ( local b2 = g(T) )
		print "g() exception done (shouldn't be printed)", b2;

	when ( local b3 = f(F) )
		{
		print "f() done, no exception", b3;
		check_term_condition();
		}

	when ( local b4 = g(F) )
		{
		print "g() done, no exception", b4;
		check_term_condition();
		}
	}
