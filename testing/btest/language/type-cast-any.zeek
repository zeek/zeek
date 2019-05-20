# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

type X: record  {
    a: addr;
    b: port;
};

function cast_to_string(a: any, b: string)
	{
	local P = (a as string);
	local Cmp = (P == b);
	print a, P, P is string, fmt("%s==%s => %s", b, P, Cmp);
	}

function cast_to_count(a: any, b: count)
	{
	local P = (a as count);
	local Cmp = (P == b);
	print a, P, P is count, fmt("%s==%s => %s", b, P, Cmp);
	}

function cast_to_X(a: any, b: X)
	{
	local P = (a as X);
	local Cmp = (P$a == b$a && P$b == b$b);
	print a, P, P is X, fmt("%s==%s => %s", b, P, Cmp);
	}

event zeek_init()
	{
	local x: X;
	x = [$a = 1.2.3.4, $b=1947/tcp];
	
	cast_to_string("Foo", "Foo");
	cast_to_string("Foo", "Bar");
	
	cast_to_count(42, 42);
	cast_to_count(42, 21);

	cast_to_X(x, [$a=1.2.3.4, $b=1947/tcp]);
	cast_to_X(x, [$a=2.3.4.5, $b=1947/tcp]);
	}


