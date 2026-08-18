# @TEST-DOC: Do not allow blank options.

# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr

module MyModule;

export {
	option _: count = 42;
}
