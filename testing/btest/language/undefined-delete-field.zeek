# @TEST-EXEC: zeek -b %INPUT  >output 2>&1 || echo $? >>output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

type MyRecordType: record
	{
	a: count;
	b: count;
	};

event zeek_init()
	{
	local x = MyRecordType($a=1, $b=2);

	delete x$c;
	}
