# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


event bro_init()
{
	local p1: port = 1/icmp;
	local p2: port = 2/udp;
	local p3: port = 3/tcp;
	local p4: port = 4/unknown;

	# maximum allowed values for each port type
	local p5: port = 255/icmp;
	local p6: port = 65535/udp;
	local p7: port = 65535/tcp;
	local p8: port = 255/unknown;

	test_case( "protocol ordering", p1 > p2 );
	test_case( "protocol ordering", p2 > p3 );
	test_case( "protocol ordering", p3 > p4 );
	test_case( "protocol ordering", p7 < p6 );
	test_case( "protocol ordering", p8 < p5 );
	test_case( "different protocol but same numeric value", p6 != p7 );
	test_case( "different protocol but same numeric value", p5 != p8 );
	test_case( "equality operator", 65535/tcp == p7 );

	# type inference
	local x = 123/tcp;
}

