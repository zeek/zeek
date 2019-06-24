# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT | sort >out
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;

type X: record {
    s: string;
    x: set[string] &optional;
};

global x1 = 42;
global x2: table[count] of X;
global x3: table[count] of X;

event quit()
{
    terminate();
}

event zeek_init()
	{
	x2[10] = [$s="foo"];
	x3[20] = [$s="bar", $x=set("i")];

	when ( x1 != 42 )
		{
		print "x1 != 42", x1 != 42;
		}
	timeout 1sec
		{
		print "unexpected timeout (1)";
		}

	when ( 15 in x2 )
		{
		print "15 in x2", 10 in x2;
		}
	timeout 1sec
		{
		print "unexpected timeout (2)";
		}

	when ( x2[10]$s == "bar" )
		{
		print "x2[10]", x2[10]$s == "bar";
		}
	timeout 1sec
		{
		print "unexpected timeout (3)";
		}

	when ( "j" in x3[20]$x )
		{
		print "unexpected trigger";
		}
	timeout 1sec
		{
		print "\"j\" in x3[20]$x, expected timeout";
		}

	x1 = 100;
	x2[15] = [$s="xyz"];
	x2[10]$s = "bar";

	# This will *NOT* trigger then when-condition because we're modifying
	# an inner value that's not directly tracked.
	add x3[20]$x["j"];

	schedule 2secs { quit() };
}

