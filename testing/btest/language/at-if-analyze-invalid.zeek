# @TEST-DOC: Tests that @if/&analyze correctly validates code in non-activated branches
# @TEST-EXEC: cat %INPUT
# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event zeek_init()
	{
	@if ( T ) &analyze
	# This should complain because it's inside a body
	warning_and_noticed_syntax_error_T
	@endif
	}

@TEST-START-NEXT

event zeek_init()
	{
	@if ( F ) &analyze
	# This should also complain because it's inside a body
	warning_and_noticed_syntax_error_F
	@endif
	}

@TEST-START-NEXT

@if ( T ) &analyze
# This should definitely complain ...
noticed_syntax_error_T
@endif

@TEST-START-NEXT

@if ( F ) &analyze
# ... and so should this, even though it's in a non-activated body
noticed_syntax_error_F
@endif

@TEST-START-NEXT

type r: record { a: count; };
type e: enum { FOO };

@if ( F ) &analyze
# Try a bunch of forbidden redef's: adding a record field, adding/removing
# attributes, extending an enum.  All should yield complaints.
redef record r += { redef_disallowed_even_though_F: bool; };
redef record r$a += { &log };
redef record r$a -= { &log };
redef enum e += { redef_disallowed_even_though_F };
@endif

@TEST-START-NEXT

@if ( F )
@if ( T ) &analyze
# Generates a warning because of if-analyze inside a non-if-analyze -
# but doesn't then analyze the body.
warning_and_unnoticed_syntax_err_T
@endif
@endif

# We add this to make sure there's *some* non-empty output.
but_a_syntax_error_here1

@TEST-START-NEXT

@if ( T )
@if ( F ) &analyze
# In this case, both a warning for the mixed nesting *and*, because the
# outer conditional is true, a complaint since we go ahead with the
# if-analyze
warning_and_noticed_syntax_err_F
@endif
@endif

@TEST-START-NEXT

# Similar test but for "@else" branches.
@if ( T )
@else
@if ( F ) &analyze
warning_and_unnoticed_syntax_err_F
@endif
@endif

but_a_syntax_error_here

@TEST-START-NEXT

# Similar test but for "@else" branches.
@if ( F )
blah blah blah
@else
@if ( T ) &analyze
warning_and_noticed_syntax_err_T
@endif
@endif

@TEST-START-NEXT

# Similar test but for "@else" branches.
@if ( F )
blah blah blah
@else
@if ( F ) &analyze
warning_and_noticed_syntax_err_F
@endif
@endif
