# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

function foo(c: count): bool
	{ return c == 42 ? T : F; }

global TRUE_CONDITION = T;

event zeek_init()
	{
	local xyz = 0;
	local local_true_condition = T;

	@if ( F )
		xyz += 1;
	@endif

	@if ( foo(0) )
		xyz += 1;
	@endif

	@if ( T && foo(42) )
		xyz += 2;
	@endif

	xyz = 0;

	@if ( F && foo(xyz) )
		xyz += 1;
	@else
		xyz += 2;
	@endif

	xyz = 0;

	@if ( T && TRUE_CONDITION && local_true_condition )
		xyz += 1;
	@else
		xyz += 2;
	@endif
	}
