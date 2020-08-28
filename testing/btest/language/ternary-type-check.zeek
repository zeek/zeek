# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath" btest-diff out

type MyRecord: record {
	a: string;
	b: count;
	c: bool &default = T;
};

event zeek_init()
	{
	local rec: MyRecord = record($a = "a string", $b = 6);
	local rec2: MyRecord = (F) ? MyRecord($a = "a string", $b = 6) :
	                             record($a = "a different string", $b = 7);
	rec2$c = F;
	}

function foo(y: count, x: count): bool
	{ return F; }

function bar(y: count): bool
	{ return F; }

function qux(a: count, b: count): bool
	{ return T; }

function myfunc(a: count, b: count)
	{
	local f = a > b ? foo : qux;
	print f(5, 7);

	local ff = a > b ? foo : bar;
	print ff(5, 7);

	local fff = a > b ? bar : foo;
	print fff(5, 7);
	}

function ternaries()
	{
	local s: set[string] = { "one" };
	local ss: set[count] = { 1 };
	local t: table[count] of string = { [1] = "one" };
	local tt: table[count] of int = { [1] = -1 };
	local v: vector of string = { "one" };
	local vv: vector of count = { 111 };
	print T ? s : s;
	print T ? t : t;
	print T ? v : v;
	print T ? s : ss;
	print T ? t : tt;
	print T ? v : vv;
	print T ? v : s;
	}
