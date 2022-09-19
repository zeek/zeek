# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O inline %INPUT >output
# @TEST-EXEC: btest-diff output

# Tests pure inlining of scripts (no other optimization/compilation used).
# The non-recursive functions should be (recursively!) inlined into the
# body of my_handler, while neither the directly-recursive nor the
# mutually recursive ones should be.

function non_recursiveA(x: double, y: double): double
	{
	return x + 2 * y;
	}

function non_recursiveB(x: double, y: double): double
	{
	# When printed, this function's body will *not* indicate inlining,
	# because this function is itself inlined (and thus will not be
	# called directly, so we avoid the work of inlining it itself).
	#
	# We reverse arguments in the call to make sure that parameters get
	# correctly assigned when executing inlined blocks.
	return x + non_recursiveA(y, x) * 3;
	}

function recursive(n: count, k: count): count
	{
	if ( n > 0 )
		return n * recursive(n-1, k + 1);
	else
		return k;
	}

global mutually_recursiveB: function(n: count, k: count): count;

function mutually_recursiveA(n: count, k: count): count
	{
	if ( n > 0 )
		return n * mutually_recursiveB(n-1, k + 1);
	else
		return k;
	}

function mutually_recursiveB(n: count, k: count): count
	{
	return mutually_recursiveA(n, k + 1);
	}

event my_handler()
	{
	print non_recursiveA(-3, 2);
	print non_recursiveB(-3, 2);
	print recursive(5, 7);
	print mutually_recursiveA(6, 4);
	}

event zeek_init()
	{
	print fmt("%s", non_recursiveA);
	print fmt("%s", non_recursiveB);
	print fmt("%s", recursive);
	print fmt("%s", mutually_recursiveA);
	print fmt("%s", mutually_recursiveB);
	print fmt("%s", my_handler);

	event my_handler();
	}
