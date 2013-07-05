# @TEST-EXEC: btest-bg-run bro bro -b --pseudo-realtime -r $TRACES/rotation.trace %INPUT
# @TEST-EXEC: btest-bg-wait -k 3
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-remove-timestamps | $SCRIPTS/diff-sort" btest-diff bro/.stderr
# @TEST-EXEC: btest-diff bro/.stdout

# interpreter exceptions in "when" blocks shouldn't cause termination

global p: pkt_hdr;

function f(do_exception: bool): bool
	{
	return when ( local addrs = lookup_hostname("localhost") )
		{
		print "localhost resolved from f()", do_exception;
		if ( do_exception )
			print p$ip;
		return T;
		}
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
			print p$ip;
		return T;
		}
	return F;
	}

event bro_init()
	{
	when ( local addrs = lookup_hostname("localhost") )
		{
		print "localhost resolved";
		print p$ip;
		}

	when ( local addrs2 = lookup_hostname("localhost") )
		{
		print "shouldn't get here";
		}
	timeout 0 sec
		{
		print "timeout";
		print p$ip;
		}

	when ( local b = f(T) )
		print "f() exception done (shouldn't be printed)", b;

	when ( local b2 = g(T) )
		print "g() exception done (shouldn't be printed)", b2;

	when ( local b3 = f(F) )
		print "f() done, no exception", b3;

	when ( local b4 = g(F) )
		print "g() done, no exception", b4;
	}
