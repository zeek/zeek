# @TEST-DOC: Locals work with the blank identifier, but can not be referenced.

# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
event zeek_init()
	{
	local _ = "1";
	}

#@TEST-START-NEXT
event zeek_init()
	{
	local _: string = "1";
	local _: count = 1;
	}

#@TEST-START-NEXT
event zeek_init()
	{
	local _: string = "1";
	const _: count = 1;
	}

#@TEST-START-NEXT
event zeek_init()
	{
	const _: string = "1";
	const _: count = 1;
	}
