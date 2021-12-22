module ClusterController::Util;

export {
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
