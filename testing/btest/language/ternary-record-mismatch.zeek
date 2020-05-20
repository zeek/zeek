# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath" btest-diff out

type MyRecord: record {
	a: string;
	b: count;
	c: bool &default = T;
};

event zeek_init()
	{
	local rec: MyRecord = record($a = "a string", $b = 6);
	local rec2: MyRecord = (F) ? MyRecord($a = "a string", $b = 6) :
	                             record($a = "a different string", $b = 7);
	rec2$c = F;
	}
