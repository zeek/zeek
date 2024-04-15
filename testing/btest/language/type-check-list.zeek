# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

type mylist: list of any;
type string_list: list of string;

function check(a: any)
	{
	print a is mylist;
	print a as mylist;
	}

event zeek_init()
	{
	local v = mylist("one", "two", 3);
	check(v);
	local sv = string_list("one", "two", "three");
	check(sv);
	}
