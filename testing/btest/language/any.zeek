# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

function anyarg(arg1: any, arg1type: string)
	{
	test_case( arg1type, type_name(arg1) == arg1type );
	}

event zeek_init()
{
	local any1: any = 5;
	local any2: any = "bar";
	local any3: any = /bar/;

	# Test using variable of type "any"

	anyarg( any1, "count" );
	anyarg( any2, "string" );
	anyarg( any3, "pattern" );

	# Test of other types

	anyarg( T, "bool" );
	anyarg( "foo", "string" );
	anyarg( 15, "count" );
	anyarg( +15, "int" );
	anyarg( 15.0, "double" );
	anyarg( /foo/, "pattern" );
	anyarg( 127.0.0.1, "addr" );
	anyarg( [::1], "addr" );
	anyarg( 127.0.0.1/16, "subnet" );
	anyarg( [ffff::1]/64, "subnet" );
	anyarg( 123/tcp, "port" );
}

