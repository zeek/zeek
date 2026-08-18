# @TEST-DOC: Assert statement wrong usage
#
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr

event zeek_init()
	{
	assert 1;
	}

# @TEST-START-NEXT
event zeek_init()
	{
	assert T, 1234;
	}

# @TEST-START-NEXT
event zeek_init()
	{
	assert;
	}

# @TEST-START-NEXT
event zeek_init()
	{
	assert T, "extra", "something";
	}
