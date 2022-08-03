# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

# IPv4 addr
global a1: addr = 192.1.2.3;

# IPv4 subnets 
global s1: subnet = 0.0.0.0/0;
global s2: subnet = 192.0.0.0/8;
global s3: subnet = 255.255.255.255/32;
global s4 = 10.0.0.0/16;

# IPv6 addrs
global b1: addr = [ffff::];
global b2: addr = [ffff::1];
global b3: addr = [ffff:1::1];

# IPv6 subnets
global t1: subnet = [::]/0;
global t2: subnet = [ffff::]/64;
global t3 = [a::]/32;

# IPv4-mapped-IPv6 subnets
global u1: subnet = [::ffff:0:0]/96;

event zeek_init()
{
	test_case( "IPv4 subnet equality", a1/8 == s2 );
	test_case( "IPv4 subnet inequality", a1/4 != s2 );
	test_case( "IPv4 subnet in operator", a1 in s2 );
	test_case( "IPv4 subnet !in operator", a1 !in s3 );
	test_case( "IPv4 subnet type inference", type_name(s4) == "subnet" );

	test_case( "IPv6 subnet equality", b1/64 == t2 );
	test_case( "IPv6 subnet inequality", b3/64 != t2 );
	test_case( "IPv6 subnet in operator", b2 in t2 );
	test_case( "IPv6 subnet !in operator", b3 !in t2 );
	test_case( "IPv6 subnet type inference", type_name(t3) == "subnet" );

	test_case( "IPv4 and IPv6 subnet inequality", s1 != t1 );
	test_case( "IPv4 address and IPv6 subnet", a1 !in t2 );

	test_case( "IPv4 in IPv4-mapped-IPv6 subnet", 1.2.3.4 in u1 );
	test_case( "IPv6 !in IPv4-mapped-IPv6 subnet", [fe80::1] !in u1 );
	test_case( "IPv4-mapped-IPv6 in IPv4-mapped-IPv6 subnet",
	           [::ffff:1.2.3.4] in u1 );
	test_case( "IPv4-mapped-IPv6 subnet equality",
	           [::ffff:1.2.3.4]/112 == 1.2.0.0/16 );
	test_case( "subnet literal const whitespace",
	           [::ffff:1.2.3.4] / 112 == 1.2.0.0 / 16 );
	test_case( "subnet literal const whitespace",
	           [::ffff:1.2.3.4]/ 128 == 1.2.3.4/ 32 );
	test_case( "subnet literal const whitespace",
	           [::ffff:1.2.3.4] /96 == 1.2.3.4 /0 );
	test_case( "subnet literal const whitespace",
	           [::ffff:1.2.3.4]   /    92 == [::fffe:1.2.3.4]    /   92 );
}

