# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff zeek/.stdout

# The 'when' implementation historically performed an AST-traversal to locate
# any index-expressions like `x[9]` and evaluated them so that it could
# register the associated value as something for which it needs to receive
# "modification" notifications.
#
# Evaluating arbitrary expressions during an AST-traversal like that ignores
# the typical order-of-evaluation/short-circuiting you'd expect if the
# condition was evaluated normally, from its root expression.  This test is
# checking that evaluation of 'when' conditions behaves according to those
# usual expectations.

redef exit_only_after_terminate = T;

type r: record {
	a: count;
};

global x: table[count] of count;
global y: table[count] of r;

const event_interval = 0.05sec;

function foo()
	{
	when ( 9 in y && y[9]$a == 3 )
		{
		print "triggered when condition against 'y'";
		terminate();
		}
	}

function bar()
	{
	when ( 9 in x && x[9] > 3 )
		print "triggered when condition against 'x'";
	}

global ev_count = 0;
event myevent()
	{
	++ev_count;
	print "running myevent", ev_count;
	local init_at = 3;

	if ( ev_count == init_at )
		{
		x[9] = 2;
		y[9] = r($a = 0);
		}
	else if ( ev_count > init_at )
		{
		++x[9];
		++y[9]$a;
		}

	schedule event_interval { myevent() };
	}

event zeek_init()
	{
	foo();
	bar();
	schedule event_interval { myevent() };
	}
