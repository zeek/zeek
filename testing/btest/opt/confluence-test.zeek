# @TEST-DOC: Regression test of ZAM analysis of complex variable "confluence".
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

global my_T: bool;

event zeek_init()
	{
	local vi: vector of int;
	local outer_var: int;
	outer_var = 0;

	# This used to throw an assertion regarding the usage regions
	# associated with outer_var.
	for ( i in vi )
		for ( n in vi )
			if ( my_T )
				break;
			else
				{
				outer_var = 1;
				break;
				}

	print outer_var;
	}
