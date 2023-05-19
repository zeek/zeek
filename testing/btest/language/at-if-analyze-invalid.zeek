# @TEST-EXEC: cat %INPUT
# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event zeek_init()
	{
	@if ( T ) &analyze
	warning_and_noticed_syntax_error_T
	@endif
	}

@TEST-START-NEXT

event zeek_init()
	{
	@if ( F ) &analyze
	warning_and_noticed_syntax_error_F
	@endif
	}

@TEST-START-NEXT

@if ( T ) &analyze
noticed_syntax_error_T
@endif

@TEST-START-NEXT

@if ( F ) &analyze
noticed_syntax_error_F
@endif

@TEST-START-NEXT

type r: record { a: count; };
type e: enum { FOO };

@if ( F ) &analyze
redef record r += { redef_disallowed_even_though_F: bool; };
redef record r$a += { &log };
redef record r$a -= { &log };
redef enum e += { redef_disallowed_even_though_F };
@endif

@TEST-START-NEXT

@if ( F )
@if ( T ) &analyze
warning_and_unnoticed_syntax_err_T
@endif
@endif

but_a_syntax_error_here

@TEST-START-NEXT

@if ( T )
@if ( F ) &analyze
warning_and_noticed_syntax_err_F
@endif
@endif

@TEST-START-NEXT

@if ( T )
@else
@if ( F ) &analyze
warning_and_unnoticed_syntax_err_F
@endif
@endif

but_a_syntax_error_here

@TEST-START-NEXT

@if ( F )
blah blah blah
@else
@if ( T ) &analyze
warning_and_noticed_syntax_err_T
@endif
@endif

@TEST-START-NEXT

@if ( F )
blah blah blah
@else
@if ( F ) &analyze
warning_and_noticed_syntax_err_F
@endif
@endif
