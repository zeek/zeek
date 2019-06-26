# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

type r: record {
	a: string;
};

event zeek_init()
	{
	# This should generate a parse error indicating that the type identifier
	# is incorrectly used in an expression expecting a real value and not
	# a value of type TypeType.
	print r$a;
	}
