# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


function f1()
	{
	test_case("no args without return value", T );
	}

function f2()
	{
	test_case("no args no return value, empty return", T );
	return;
	}

function f3(): bool 
	{
	return T;
	}

function f4(test: string)
	{
	test_case("args without return value", T );
	}

function f5(test: string): bool 
	{
	return T;
	}

function f6(test: string, num: count): bool 
	{
	local val: int = -num;
	if ( test == "bar" && num == 3 && val < 0 ) return T;
	return F;
	}

function f7(test: string): bool 
	{
	return F;
	}

event zeek_init()
{
	f1();
	f2();
	test_case("no args with return value", f3() );
	f4("foo");
	test_case("args with return value", f5("foo") );
	test_case("multiple args with return value", f6("bar", 3) );

	local f10 = function() { test_case("anonymous function without args or return value", T ); };
	f10();

	local f11 = function(): bool { return T; };
	test_case("anonymous function with return value", f11() );

	local f12 = function(val: int): bool { if (val > 0) return T; else return F; };
	test_case("anonymous function with args and return value", f12(2) );

	# Test that a function variable can later be assigned to a function
	local f13: function(test: string): bool;
	f13 = f5;
	test_case("assign function variable", f13("foo") );
	f13 = f7;
	test_case("reassign function variable", !f13("bar") );
}

