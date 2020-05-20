# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

global ct: count;

function t_func(): bool
        {
	ct += 1;
	return T;
        }

function f_func(): bool
        {
	ct += 2;
	return F;
        }


event zeek_init()
{
	local res: bool;

	# both functions should be called
	ct = 0;
	res = t_func() && f_func();
	test_case("&& operator (eval. both operands)", res == F && ct == 3 );

	# only first function should be called
	ct = 0;
	res = f_func() && t_func();
	test_case("&& operator (eval. 1st operand)", res == F && ct == 2 );

	# only first function should be called
	ct = 0;
	res = t_func() || f_func();
	test_case("|| operator (eval. 1st operand)", res == T && ct == 1 );

	# both functions should be called
	ct = 0;
	res = f_func() || t_func();
	test_case("|| operator (eval. both operands)", res == T && ct == 3 );
}

