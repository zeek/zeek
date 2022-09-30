# @TEST-DOC: Do not allow blank options.

# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

module MyModule;

export {
	option _: count = 42;
}
