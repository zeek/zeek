# @TEST-EXEC: zeek -b valid.zeek 2>valid.stderr 1>valid.stdout
# @TEST-EXEC: btest-diff valid.stderr
# @TEST-EXEC: btest-diff valid.stdout

# @TEST-EXEC-FAIL: zeek -b invalid.zeek 2>invalid.stderr 1>invalid.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff invalid.stderr
# @TEST-EXEC: btest-diff invalid.stdout

@TEST-START-FILE valid.zeek
# First some simple code that should be valid and error-free.

function f(c: count)
	{
	print "enter f", c;
	c = c + 100;
	print "exit f", c;
	}

const foo = 0 &redef;
redef foo = 10;

const bar = 9;

event zeek_init()
	{
	const baz = 7;
	local i = foo;
	i = i + bar + 2;
	i = i + baz + 11;
	++i;
	print i;
	--i;
	f(foo);
	f(bar);
	f(baz);
	print "foo", foo;
	print "bar", bar;
	print "baz", baz;
	}

@TEST-END-FILE

@TEST-START-FILE invalid.zeek
# Now some const assignments that should generate errors at parse-time.

const foo = 0 &redef;
redef foo = 10;

const bar = 9;

event zeek_init()
	{
	const baz = 7;
	local s = 0;

	print "nope";

	foo = 100;
	foo = bar;
	foo = bar = baz;
	foo = s;
	++foo;
	s = foo = bar;

	if ( foo = 0 )
		print "nope";

	bar = 1 + 1;
	baz = s;
	++bar;
	--baz;

	print "foo", foo;
	print "bar", bar;
	print "baz", baz;
	print "foo=foo", foo = foo;
	}

@TEST-END-FILE
