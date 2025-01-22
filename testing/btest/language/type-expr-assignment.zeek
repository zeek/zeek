# @TEST-DOC: Ensure redefining a type expression ID is an error
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

event zeek_init()
	{
	local str = string;
	str = count;
	local my_string: str; # This will still be a string
	}
