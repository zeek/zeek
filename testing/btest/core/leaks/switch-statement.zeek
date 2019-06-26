# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-bg-wait 60

type MyEnum: enum {
	RED,
	GREEN,
	BLUE,
	PINK,
};

function switch_bool(v: bool): string
	{
	switch (v) {
	case T:
		return "true";
	case F:
		return "false";
	}
	return "n/a";
	}

function switch_int(v: int): string
	{
	switch (v) {
	case +1:
		return "one";
	case +2:
		return "two";
	case -3:
		return "minus three";
	}
	return "n/a";
	}

function switch_enum(v: MyEnum): string
	{
	switch (v) {
	case RED:
		return "red";
	case GREEN:
		return "green";
	case BLUE:
		return "blue";
	}
	return "n/a";
	}

function switch_count(v: count): string
	{
	switch (v) {
	case 1:
		return "1";
	case 2:
		return "2";
	case 3:
		return "3";
	}
	return "n/a";
	}

function switch_port(v: port): string
	{
	switch (v) {
	case 22/tcp:
		return "ssh";
	case 53/udp:
		return "dns";
	case 0/icmp:
		return "echo";
	}
	return "n/a";
	}

function switch_double(v: double): string
	{
	switch (v) {
	case 1.1:
		return "1.1";
	case 2.2:
		return "2.2";
	case 3.3:
		return "3.3";
	}
	return "n/a";
	}

function switch_interval(v: interval): string
	{
	switch (v) {
	case 1sec:
		return "1sec";
	case 2day:
		return "2day";
	case 3min:
		return "3min";
	}
	return "n/a";
	}

function switch_string(v: string): string
	{
	switch (v) {
	case "one":
		return "first";
	case "two":
		return "second";
	case "three":
		return "third";
	}
	return "n/a";
	}

function switch_addr(v: addr): string
	{
	switch (v) {
	case 1.2.3.4:
		return "ipv4";
	case [fe80::1]:
		return "ipv6";
	case 0.0.0.0:
		return "unspec";
	}
	return "n/a";
	}

function switch_subnet(v: subnet): string
	{
	switch (v) {
	case 1.2.3.0/24:
		return "1.2.3.0/24";
	case [fe80::0]/96:
		return "[fe80::0]";
	case 192.168.0.0/16:
		return "192.168.0.0/16";
	}
	return "n/a";
	}

function switch_empty(v: count): string
	{
	switch ( v ) {
	}
	return "n/a";
	}

function switch_fallthrough(v: count): string
	{
	local rval = "";
	switch ( v ) {
	case 1:
		rval += "test";
		fallthrough;
	case 2:
		rval += "testing";
		fallthrough;
	case 3:
		rval += "tested";
		break;
	}
	return rval + "return";
	}

function switch_default(v: count): string
	{
	local rval = "";
	switch ( v ) {
	case 1:
		rval += "1";
		fallthrough;
	case 2:
		rval += "2";
		break;
	case 3:
		rval += "3";
		fallthrough;
	default:
		rval += "d";
		break;
	}
	return rval + "r";
	}

function switch_default_placement(v: count): string
	{
	local rval = "";
	switch ( v ) {
	case 1:
		rval += "1";
		fallthrough;
	default:
		rval += "d";
		fallthrough;
	case 2:
		rval += "2";
		break;
	case 3:
		rval += "3";
		break;
	}
	return rval + "r";
	}

function switch_case_list(v: count): string
	{
	switch ( v ) {
	case 1, 2:
		return "1,2";
	case 3, 4, 5:
		return "3,4,5";
	case 6, 7, 8, 9:
		return "6,7,8,9";
	}
	return "n/a";
	}

function test_switch(actual: string, expect: string)
	{
	if ( actual != expect )
		print fmt("%s != %s", actual, expect);
	}

event new_connection(c: connection)
	{
	test_switch( switch_bool(T) , "true" );
	test_switch( switch_bool(F) , "false" );
	test_switch( switch_int(+1) , "one" );
	test_switch( switch_int(+2) , "two" );
	test_switch( switch_int(-3) , "minus three" );
	test_switch( switch_int(40) , "n/a" );
	test_switch( switch_enum(RED) , "red" );
	test_switch( switch_enum(BLUE) , "blue" );
	test_switch( switch_enum(GREEN) , "green" );
	test_switch( switch_enum(PINK) , "n/a" );
	test_switch( switch_count(1) , "1" );
	test_switch( switch_count(2) , "2" );
	test_switch( switch_count(3) , "3" );
	test_switch( switch_count(100) , "n/a" );
	test_switch( switch_port(22/tcp) , "ssh" );
	test_switch( switch_port(53/udp) , "dns" );
	test_switch( switch_port(0/icmp) , "echo" );
	test_switch( switch_port(1000/tcp) , "n/a" );
	test_switch( switch_double(1.1) , "1.1" );
	test_switch( switch_double(2.2) , "2.2" );
	test_switch( switch_double(3.3) , "3.3" );
	test_switch( switch_interval(1sec) , "1sec" );
	test_switch( switch_interval(2day) , "2day" );
	test_switch( switch_interval(3min) , "3min" );
	test_switch( switch_string("one") , "first" );
	test_switch( switch_string("two") , "second" );
	test_switch( switch_string("three") , "third" );
	test_switch( switch_addr(1.2.3.4) , "ipv4" );
	test_switch( switch_addr([fe80::1]) , "ipv6" );
	test_switch( switch_addr(0.0.0.0) , "unspec" );
	test_switch( switch_subnet(1.2.3.4/24) , "1.2.3.0/24" );
	test_switch( switch_subnet([fe80::1]/96) , "[fe80::0]" );
	test_switch( switch_subnet(192.168.1.100/16) , "192.168.0.0/16" );
	test_switch( switch_empty(2) , "n/a" );
	test_switch( switch_fallthrough(1) , "testtestingtestedreturn" );
	test_switch( switch_fallthrough(2) , "testingtestedreturn" );
	test_switch( switch_fallthrough(3) , "testedreturn" );
	test_switch( switch_default(1) , "12r" );
	test_switch( switch_default(2) , "2r" );
	test_switch( switch_default(3) , "3dr" );
	test_switch( switch_default(4) , "dr" );
	test_switch( switch_default_placement(1) , "1d2r" );
	test_switch( switch_default_placement(2) , "2r" );
	test_switch( switch_default_placement(3) , "3r" );
	test_switch( switch_default_placement(4) , "d2r" );

	local v = vector(0,1,2,3,4,5,6,7,9,10);
	local expect: string;

	for ( i in v )
		{
		switch ( v[i] ) {
		case 1, 2:
			expect = "1,2";
			break;
		case 3, 4, 5:
			expect = "3,4,5";
			break;
		case 6, 7, 8, 9:
			expect = "6,7,8,9";
			break;
		default:
			expect = "n/a";
			break;
		}
		test_switch( switch_case_list(v[i]) , expect );
		}

	print "done";
	}
