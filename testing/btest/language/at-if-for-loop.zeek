# @TEST-DOC: Test related to #2289: With Zeek 5.0 this printed "yes" once, now it prints 3 times.
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout

event zeek_init()
	{
	local v = vector(1, 2, 3);
	for ( i in v )
@if ( T )
		print "yes";
@endif
	}

@TEST-START-NEXT

event zeek_init()
	{
	local v = vector(1, 2, 3);
	for ( i in v )
@if ( T )
		print "yes";
@else
		print "no";
@endif
	}
