# These tests show off common scripting mistakes, which should be
# handled internally by way of throwing an exception to unwind out
# of the current event handler body.

# @TEST-EXEC: zeek -b 1.zeek >1.out 2>1.err
# @TEST-EXEC: btest-diff 1.out
# @TEST-EXEC: btest-diff 1.err

# @TEST-EXEC: zeek -b 2.zeek >2.out 2>2.err
# @TEST-EXEC: btest-diff 2.out
# @TEST-EXEC: btest-diff 2.err

@TEST-START-FILE 1.zeek
type myrec: record {
	f: string &optional;
};

function foo(mr: myrec)
	{
	print "foo start";
	# Uninitialized field access: unwind out of current event handler body
	print mr$f;
	# Unreachable
	print "foo done";
	}

function bar()
	{
	print "bar start";
	foo(myrec());
	# Unreachable
	print "bar done";
	}

event zeek_init()
	{
	bar();
	# Unreachable
	print "zeek_init done";
	}

event zeek_init() &priority=-10
	{
	# Reachable
	print "other zeek_init";
	}
@TEST-END-FILE

@TEST-START-FILE 2.zeek
function foo()
	{
	print "in foo";
	local t: table[string] of string = table();

	# Non-existing index access: (sub)expressions should not be evaluated
	if ( t["nope"] == "nope" )
		# Unreachable
		print "yes";
	else
		# Unreachable
		print "no";

	# Unreachable
	print "foo done";
	}

event zeek_init()
	{
	foo();
	# Unreachable
	print "zeek_init done";
	}

@TEST-END-FILE
