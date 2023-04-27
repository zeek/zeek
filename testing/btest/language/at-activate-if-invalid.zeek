# @TEST-EXEC: cat %INPUT
# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event zeek_init()
	{
	@activate-if ( T )
	warning_and_noticed_syntax_error_T
	@endif
	}

@TEST-START-NEXT

event zeek_init()
	{
	@activate-if ( F )
	warning_and_noticed_syntax_error_F
	@endif
	}

@TEST-START-NEXT

@activate-if ( T )
noticed_syntax_error_T
@endif

@TEST-START-NEXT

@activate-if ( F )
noticed_syntax_error_F
@endif

@TEST-START-NEXT

type r: record { a: count; };
type e: enum { FOO };

@activate-if ( F )
redef record r += { redef_disallowed_even_though_F: bool; };
redef record r$a += { &log };
redef record r$a -= { &log };
redef enum e += { redef_disallowed_even_though_F };
@endif

@TEST-START-NEXT

@if ( F )
@activate-if ( T )
warning_and_unnoticed_syntax_err_T
@endif
@endif

but_a_syntax_error_here

@TEST-START-NEXT

@if ( T )
@activate-if ( F )
warning_and_noticed_syntax_err_F
@endif
@endif

@TEST-START-NEXT

@if ( T )
@else
@activate-if ( F )
warning_and_unnoticed_syntax_err_F
@endif
@endif

but_a_syntax_error_here

@TEST-START-NEXT

@if ( F )
blah blah blah
@else
@activate-if ( T )
warning_and_noticed_syntax_err_T
@endif
@endif

@TEST-START-NEXT

@if ( F )
blah blah blah
@else
@activate-if ( F )
warning_and_noticed_syntax_err_F
@endif
@endif
