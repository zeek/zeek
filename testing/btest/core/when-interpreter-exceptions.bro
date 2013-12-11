# @TEST-EXEC: btest-bg-run bro "bro -b --pseudo-realtime -r $TRACES/rotation.trace %INPUT >output 2>&1"
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-remove-timestamps | $SCRIPTS/diff-sort" btest-diff bro/output

# interpreter exceptions in "when" blocks shouldn't cause termination

global p: pkt_hdr;

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
	return when ( local addrs = lookup_hostname("localhost") )
		{
		print "localhost resolved from f()", do_exception;

		if ( do_exception )
			{
			event termination_check();
			print p$ip;
			}

		return T;
		}
	timeout 10 sec
		{
		print "lookup_hostname in f() timed out unexpectedly";
		}

	check_term_condition();
	return F;
	}

function g(do_exception: bool): bool
	{
	return when ( local addrs = lookup_hostname("localhost") )
		{
		print "shouldn't get here, g()", do_exception;
		}
	timeout 0 sec
		{
		print "timeout g()", do_exception;

		if ( do_exception )
			{
			event termination_check();
			print p$ip;
			}

		return T;
		}

	check_term_condition();
	return F;
	}

event bro_init()
	{
	when ( local addrs = lookup_hostname("localhost") )
		{
		print "localhost resolved";
		event termination_check();
		print p$ip;
		}
	timeout 10 sec
		{
		print "lookup_hostname timed out unexpectedly";
		check_term_condition();
		}

	when ( local addrs2 = lookup_hostname("localhost") )
		{
		print "shouldn't get here";
		check_term_condition();
		}
	timeout 0 sec
		{
		print "timeout";
		event termination_check();
		print p$ip;
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
