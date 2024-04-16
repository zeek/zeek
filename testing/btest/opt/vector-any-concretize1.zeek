# @TEST-DOC: Regression test for past ZAM issues with vector-of-any.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

function vector_copy(v: vector of any): vector of any
	{
	# This seems like an unnecessary initialization given the ensuing
	# copy, but we preserve it because it's from the original script
	# that triggered the need for some fixes, hence it's the full
	# regression.
	local v2 = copy(v);

	for ( i in v )
		v2[i] = v[i];

	return v2;
	}

event zeek_init()
	{
	local v = vector(5, 3, 9);
	local v_copy = vector_copy(v);
	print v_copy;
	}
