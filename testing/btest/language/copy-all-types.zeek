# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

function check(o1: any, o2: any, equal: bool, expect_same: bool)
	{
	local expect_msg = (equal ? "ok" : "FAIL0");
	local same = same_object(o1, o2);

	if ( expect_same && ! same )
		expect_msg = "FAIL1";

	if ( ! expect_same && same )
		expect_msg = "FAIL2";
	
	print fmt("orig=%s (%s) clone=%s (%s) equal=%s same_object=%s (%s)", o1, type_name(o1), o2, type_name(o2), equal, same, expect_msg);
	}

event zeek_init()
	{
	local i1 = -42;
	local i2 = copy(i1);
	check(i1, i2, i1 == i2, T);
	
	local s1 = "Foo";
	local s2 = copy(s1);
	check(s1, s2, s1 == s2, F);
	}
