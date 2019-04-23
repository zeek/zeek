#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: test -f .state/state.bst

event zeek_init()
	{
	local a = checkpoint_state();
	if ( a != T )
		exit(1);
	}
