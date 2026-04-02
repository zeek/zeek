# @TEST-DOC: Regression test for constructing a table with an "any" yield type
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

type tbl_of_any: table[string] of any;  

function build_tbl_of_any()
        {
        local fn = "foo";
        print tbl_of_any([fn] = 3);
        }

event zeek_init()
	{
	build_tbl_of_any();
	print "I ran";
	}
