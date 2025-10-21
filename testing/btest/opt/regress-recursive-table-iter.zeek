# @TEST-DOC: Regression test for function recursing while iterating over a table
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

function recurse(tbl: table[count] of count)
	{
	print "recursing", tbl;

	if ( |tbl| == 0 )
		return;

	for ( key in tbl )
		{
		local sub_tbl = copy(tbl);
		delete sub_tbl[key];
		recurse(sub_tbl);
		}
	}

event zeek_init()
	{
	recurse(table([1] = 10, [2] = 20));
	}
