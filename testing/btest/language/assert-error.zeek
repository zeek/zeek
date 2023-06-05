# @TEST-DOC: Assert statement wrong usage
#
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

event zeek_init()
	{
	assert 1;
	}

@TEST-START-NEXT
event zeek_init()
	{
	assert T, 1234;
	}

@TEST-START-NEXT
event zeek_init()
	{
	assert;
	}

@TEST-START-NEXT
event zeek_init()
	{
	assert T, "extra", "something";
	}
