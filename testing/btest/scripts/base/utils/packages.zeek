# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

@load base/utils/packages

@if ( can_load("pkg1") )
@load pkg1
@endif

@if ( can_load("pkg2") )
@load pkg2
@endif

@if ( can_load("pkg3") )
@load pkg3
@else
print "no pkg3";
@endif

# @TEST-START-FILE pkg1.zeek
event zeek_init()
	{
	print "pkg1!";
	}
# @TEST-END-FILE

# @TEST-START-FILE pkg2/__load__.zeek
event zeek_init()
	{
	print "pkg2!";
	}
# @TEST-END-FILE
