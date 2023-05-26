# @TEST-DOC: Makes sure that code inside not-taken @if/&analyze blocks has its effects correctly unwound
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

global yep = T &redef;
global nope = F &redef;
global redef_me = 0 &redef;

@if ( nope ) &analyze
	redef nope = F;
	event zeek_init() # this should not run
		{
		print "hi #1!", nope, redef_me;
		}

	# Neither of these redef's should have lasting effect.
	@if ( nope ) &analyze
		redef redef_me = 1;
	@else
		redef redef_me = 2;
	@endif
@endif

@if ( yep ) &analyze
	redef yep = F;
	global old_redef_me = redef_me;
	event zeek_init() # this should run
		{
		print "hi #2!", yep, old_redef_me, redef_me;
		}

	@if ( yep ) &analyze
		redef redef_me = 3;
	@else
		redef redef_me = 4; # we expect this, since we redef'd "yep"
	@endif
@endif

function side_effects(msg: string): bool
	{
	print "I got called!", msg;
	return T;
	}

global my_table: table[count] of string &default="no redef" &redef;

@if ( T ) &analyze
global z = side_effects("should happen");
redef my_table: table[count] of string &default="redef #1";
@endif

@if ( F ) &analyze
# Tricky - need to parse/validate the declaration, but not do the init
global z = side_effects("shouldn't happen");
redef my_table: table[count] of string &default="redef #2";
@endif

# Okay, which &default did we actually pick up?
print my_table[5];

@if ( T ) &analyze
	@if ( F ) &analyze
		print "T/F";
	@else
		# We expect this one
		print "T/!F";
	@endif
@else
	# We expect none of these
	@if ( F ) &analyze
		print "!T/F";
	@else
		print "!T/!F";
	@endif
@endif

@if ( F ) &analyze
	# We expect none of these
	@if ( F ) &analyze
		print "F/F";
	@else
		print "F/!F";
	@endif
@else
	@if ( T ) &analyze
		# We expect this one
		print "!F/T";
	@else
		print "!F/!T";
	@endif
@endif
