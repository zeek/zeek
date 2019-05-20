# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out


function f1(test: string)
	{
	;  # null statement in function
	}

event zeek_init()
{
	local s1: set[string] = set( "this", "test" );

	; # null statement in event

	for ( i in s1 )
		;  # null statement in for loop

	if ( |s1| > 0 ) ;  # null statement in if statement

	f1("foo");

	{ ; }  # null compound statement

	if ( |s1| == 0 ) 
		{
		print "Error: this should not happen";
		}
	else
		;  # null statement in else

	print "done";
}

