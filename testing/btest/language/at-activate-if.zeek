# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

global yep = T &redef;
global nope = F &redef;
global redef_me = 0 &redef;

@activate-if ( nope )
	redef nope = F;
	event zeek_init()
		{
		print "hi #1!", nope, redef_me;
		}

	@activate-if ( nope )
		redef redef_me = 1;
	@else
		redef redef_me = 2;
	@endif
@endif

@activate-if ( yep )
	redef yep = F;
	global old_redef_me = redef_me;
	event zeek_init()
		{
		print "hi #2!", yep, old_redef_me, redef_me;
		}

	@activate-if ( yep )
		redef redef_me = 3;
	@else
		redef redef_me = 4;
	@endif
@endif

function side_effects(msg: string): bool
	{
	print "I got called!", msg;
	return T;
	}

global my_table: table[count] of string &default="no redef" &redef;

@activate-if ( T )
global z = side_effects("should happen");
redef my_table: table[count] of string &default="redef #1";
@endif

@activate-if ( F )
global z = side_effects("shouldn't happen");
redef my_table: table[count] of string &default="redef #2";
@endif

print my_table[5];

@activate-if ( T )
	@activate-if ( F )
		print "T/F";
	@else
		print "T/!F";
	@endif
@else
	@activate-if ( F )
		print "!T/F";
	@else
		print "!T/!F";
	@endif
@endif

@activate-if ( F )
	@activate-if ( F )
		print "F/F";
	@else
		print "F/!F";
	@endif
@else
	@activate-if ( T )
		print "!F/T";
	@else
		print "!F/!T";
	@endif
@endif
