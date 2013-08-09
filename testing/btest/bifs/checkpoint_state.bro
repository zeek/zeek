#
# @TEST-EXEC: bro -b %INPUT
# @TEST-EXEC: test -f .state/state.bst

event bro_init()
	{
	local a = checkpoint_state();
	if ( a != T )
		exit(1);
	}
