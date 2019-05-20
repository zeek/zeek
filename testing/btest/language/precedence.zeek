# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

# This is an incomplete set of tests to demonstrate the order of precedence
# of zeek script operators

event zeek_init()
{
	local n1: int;
	local n2: int;
	local n3: int;

	# Tests that show "++" has higher precedence than "*"

	n1 = n2 = 5;
	n1 = ++n1 * 3;
	n2 = (++n2) * 3;
	test_case( "++ and *", n1 == 18 );
	test_case( "++ and *", n2 == 18 );

	n1 = 5;
	n1 = 3 * ++n1;
	test_case( "* and ++", n1 == 18 );

	# Tests that show "*" has same precedence as "%"

	n1 = 3 * 5 % 2;
	n2 = (3 * 5) % 2;
	n3 = 3 * (5 % 2);
	test_case( "* and %", n1 == 1 );
	test_case( "* and %", n2 == 1 );
	test_case( "* and %", n3 == 3 );

	n1 = 7 % 3 * 2;
	n2 = (7 % 3) * 2;
	n3 = 7 % (3 * 2);
	test_case( "% and *", n1 == 2 );
	test_case( "% and *", n2 == 2 );
	test_case( "% and *", n3 == 1 );

	# Tests that show "*" has higher precedence than "+"

	n1 = 1 + 2 * 3;
	n2 = 1 + (2 * 3);
	n3 = (1 + 2) * 3;
	test_case( "+ and *", n1 == 7 );
	test_case( "+ and *", n2 == 7 );
	test_case( "+ and *", n3 == 9 );

	# Tests that show "+" has higher precedence than "<"

	test_case( "< and +", 5 < 3 + 7 );
	test_case( "< and +", 5 < (3 + 7) );

	test_case( "+ and <", 7 + 3 > 5 );
	test_case( "+ and <", (7 + 3) > 5 );

	# Tests that show "+" has higher precedence than "+="

	n1 = n2 = n3 = 0;
	n1 += 1 + 2;
	n2 += (1 + 2);
	(n3 += 1) + 2;
	test_case( "+= and +", n1 == 3 );
	test_case( "+= and +", n2 == 3 );
	test_case( "+= and +", n3 == 1 );

	local r1: bool;
	local r2: bool;
	local r3: bool;

	# Tests that show "&&" has higher precedence than "||"

	r1 = F && F || T;
	r2 = (F && F) || T;
	r3 = F && (F || T);
	test_case( "&& and ||", r1 );
	test_case( "&& and ||", r2 );
	test_case( "&& and ||", !r3 );

	r1 = T || F && F;
	r2 = T || (F && F);
	r3 = (T || F) && F;
	test_case( "|| and &&", r1 );
	test_case( "|| and &&", r2 );
	test_case( "|| and &&", !r3 );

	# Tests that show "||" has higher precedence than conditional operator

	r1 = T || T ? F : F;
	r2 = (T || T) ? F : F;
	r3 = T || (T ? F : F);
	test_case( "|| and conditional operator", !r1 );
	test_case( "|| and conditional operator", !r2 );
	test_case( "|| and conditional operator", r3 );

	r1 = T ? F : F || T;
	r2 = T ? F : (F || T);
	r3 = (T ? F : F) || T;
	test_case( "conditional operator and ||", !r1 );
	test_case( "conditional operator and ||", !r2 );
	test_case( "conditional operator and ||", r3 );

}

