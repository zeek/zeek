
@load ./main

module GLOBAL;

## This is the entry point in the global namespace for the notice framework.
function NOTICE(n: Notice::Info)
	{
	# Suppress this notice if necessary.
	if ( Notice::is_being_suppressed(n) )
		return;

	Notice::internal_NOTICE(n);
	}
