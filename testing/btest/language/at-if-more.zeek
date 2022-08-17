# @TEST-DOC: Various @if / @ifdef / @ifndef tests taht failed while working on #2289
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout

event zeek_init()
	{
@if ( T )
	if ( T )
		print "That's the right branch";
@endif
	}

@TEST-START-NEXT

global Mumble = 5;

event zeek_init()
	{
@ifdef ( Mumble )
	if ( T )
		print "That's the right branch";
@endif
	}

@TEST-START-NEXT

global Mumble = 5;

event zeek_init()
	{
@ifdef ( Mumble )
	if ( F )
		print "That's the wrong branch";
	else
		print "That's the right branch";
@endif
	}

@TEST-START-NEXT

event zeek_init()
	{
@ifndef ( Mumble )
	if ( T )
		print "That's the right branch";
	else
		print "That's the wrong branch";
@endif
	}

@TEST-START-NEXT

event zeek_init()
	{
@ifdef ( Mumble )
	if ( T )
		print "That's the wrong branch";
@endif
	print "Not other output expected";
	}

@TEST-START-NEXT

global Mumble = 5;

event zeek_init()
	{
@ifdef ( Mumble )
	if ( T )
		print "That is the right branch";
@else
	if ( T )
		print "That's the wrong branch";
@endif
	}

@TEST-START-NEXT

event zeek_init()
	{
@if ( F )
	if ( T )
		print "That's the wrong branch";
@else
	if ( T )
		print "That is the right branch";
@endif
	}

@TEST-START-NEXT
event zeek_init()
	{
@ifdef ( Mumble )
	if ( T )
		print "That's the wrong branch";
@else
	if ( T )
		print "That is the right branch";
@endif
	}

@TEST-START-NEXT
event zeek_init()
	{
@if ( T )
	print "That is the right branch 1";
	print "That is the right branch 2";
@else
	print "That is the wrong branch";
@endif
	}

@TEST-START-NEXT
event zeek_init()
	{
@if ( T )
	{
	print "That is the right branch 1";
	print "That is the right branch 2";
	}
@else
	{
	print "That is the wrong branch";
	}
@endif
	}
