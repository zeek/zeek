# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

# Check if @if can be used to alternative function/event definitions

@if ( 1==1 )
function test_case(msg: string)
@else
lalala
@endif
	{
	print msg;
	}

@if ( 1==1 )
event zeek_init() &priority=9
@else
lalala
@endif
	{
	print "1";
	test_case("2");
	}

@if ( 1==0 )
lalala
@else
event zeek_init() &priority=8
@endif
	{
	print "3";
	}

@if ( 1==1 )
@if ( 1==1 )
event zeek_init() &priority=7
@endif
@else
lalala
@endif
	{
	print "4";
	}

@if ( 1==1 )
event zeek_init() &priority=10
@else
lalala
@endif
	{
	print "0";
	}
