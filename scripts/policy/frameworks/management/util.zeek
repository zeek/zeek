##! Utility functions for the Management framework, available to agent
##! and controller.

module Management::Util;

export {
	## Renders a set of strings to an alphabetically sorted vector.
	##
	## ss: the string set to convert.
	##
	## Returns: the vector of all strings in ss.
	global set_to_vector: function(ss: set[string]): vector of string;
}

function set_to_vector(ss: set[string]): vector of string
	{
	local res: vector of string;

	for ( s in ss )
		res[|res|] = s;

	sort(res, strcmp);

	return res;
	}
