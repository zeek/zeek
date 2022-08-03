# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

function test_case(msg: string, expect: bool)
	{
	print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
	}

global ct: count;

function f1(): bool
	{
	ct += 1;
	return T;
	}

function f2(): bool
	{
	ct += 4;
	return F;
	}

# The following needs to be a global to test for a ZAM regression where
# the ZAM optimizer will optimize away the problematic condition if the
# value is constant.
global false = F;

global a: count;
global b: count;
global res: count;
global res2: bool;

global s: set[string] = { "one", "two", "three" };
global t: table[count] of string = { [1] = "one", [2] = "two", [3] = "three" };
global v: vector of string = { "one", "two", "three" };

event zeek_init()
	{
	# Test that the correct operand is evaluated

	a = b = 0;
	res = T ? ++a : ++b;
	test_case( "true condition", a == 1 && b == 0 && res == 1);

	a = b = 0;
	res = F ? ++a : ++b;
	test_case( "false condition", a == 0 && b == 1 && res == 1);

	# Test again using function calls as operands

	ct = 0;
	res2 = ct == 0 ? f1() : f2();
	test_case( "true condition", ct == 1 && res2 == T);

	ct = 0;
	res2 = ct != 0 ? f1() : f2();
	test_case( "false condition", ct == 4 && res2 == F);

	# Test that the conditional operator is right-associative

	ct = 0;
	T ? f1() : T ? f1() : f2();
	test_case( "associativity", ct == 1 );

	ct = 0;
	T ? f1() : (T ? f1() : f2());
	test_case( "associativity", ct == 1 );

	ct = 0;
	(T ? f1() : T) ? f1() : f2();
	test_case( "associativity", ct == 2 );

	# Test for unspecified set coercion
	local sT = T ? set() : s;
	local sF = F ? s : set();
	print |sT|, type_name(sT);
	print |sF|, type_name(sF);

	# Test for unspecified table coercion
	local tT = T ? table() : t;
	local tF = F ? t : table();
	print |tT|, type_name(tT);
	print |tF|, type_name(tF);

	# Test for unspecified vector coercion
	local vT = T ? vector() : v;
	local vF = F ? v : vector();
	print |vT|, type_name(vT);
	print |vF|, type_name(vF);

	# Test for ternary vector condition
	local tvc = vector(T, F, T);
	local tvr = tvc ? vector(1, 2, 3) : vector(4, 5, 6);
	print tvr, type_name(tvr);

	# Test for ternary results
	local tvr2 = false ? vector(1, 2, 3) : vector(4, 5, 6);
	print tvr2, type_name(tvr2);
	}
