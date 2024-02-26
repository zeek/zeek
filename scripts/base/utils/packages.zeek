##! Rudimentary functions for helping with Zeek packages.

## Checks whether @load of a given package name could
## be successful.
##
## This tests for the existence of corresponding script files
## in ZEEKPATH. It does not attempt to parse and validate
## any actual Zeek script code.
##
## path: The filename, package or path to test.
##
## Returns: T if the given filename, package or path may load.
function can_load(p: string): bool
	{
	return find_in_zeekpath(p) != "";
	}
