# @TEST-DOC: Test for #2289 showing that @if  works better.
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout

global cond = T;
event zeek_init()
	{
	if ( F )
		@if ( cond  )
			print "Bad branch true";
		@else
			print "Bad branch false";
		@endif
	else
		print "That's the right branch";
	}

@TEST-START-NEXT
global cond = T;
event zeek_init()
	{
	if ( T )
		@if ( cond  )
			print "That's the right branch";
		@else
			print "Bad branch false";
		@endif
	else
		print "Bad branch outer else";
	}

@TEST-START-NEXT
global cond = T;
event zeek_init()
	{
	if ( T )
		{
		@if ( cond  )
			print "That's the right branch";
		@else
			print "Bad branch false";
		@endif
		}
	else
		print "Bad branch outer else";
	}

@TEST-START-NEXT
global cond = T;
event zeek_init()
	{
	if ( F )
		{
		@if ( cond  )
			print "Bad branch true";
		@else
			print "Bad branch false";
		@endif
		}
	else
		print "That's the right branch";
	}
