# @TEST-DOC: Test for #2289 - reject directives appearing as statements
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

event zeek_init()
	{
	if ( F )
		@if ( T )
			print "Bad branch true";
		@else
			print "Bad branch false";
		@endif
	else
		print "That's the right branch";
	}

@TEST-START-NEXT
event zeek_init()
	{
	if ( F )
		print "That would be okay";
	else
		@if ( T )
			print "That isn't";
		@endif
	}

@TEST-START-NEXT
event zeek_init()
	{
	local vec = vector(1, 2, 3);
	for ( i in vec )
		@if ( T )
			print "Bad branch true";
		@endif
	}

@TEST-START-NEXT
event zeek_init()
	{
	local i = 10;
	while ( --i != 0 )
		@if ( T )
			print "Bad branch true";
		@endif
	}

@TEST-START-NEXT
global cond = T;
event zeek_init()
	{
	local vec = vector(1, 2, 3);
	for ( i in vec )
		@if ( cond  )
			print "Bad branch true";
		@endif
	}
