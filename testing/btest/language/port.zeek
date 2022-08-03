# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

global p1: port = 1/icmp;
global p2: port = 2/udp;
global p3: port = 3/tcp;
global p4: port = 4/unknown;
global p5 = 123/tcp;

# maximum allowed values for each port type
global p6: port = 255/icmp;
global p7: port = 65535/udp;
global p8: port = 65535/tcp;
global p9: port = 255/unknown;

event zeek_init()
{
	# Type inference test

	test_case( "type inference", type_name(p5) == "port" );

	# Operator tests

	test_case( "protocol ordering", p1 > p2 );
	test_case( "protocol ordering", p2 > p3 );
	test_case( "protocol ordering", p3 > p4 );
	test_case( "protocol ordering", p8 < p7 );
	test_case( "protocol ordering", p9 < p6 );
	test_case( "different protocol but same numeric value", p7 != p8 );
	test_case( "different protocol but same numeric value", p6 != p9 );
	test_case( "equality operator", 65535/tcp == p8 );

}

