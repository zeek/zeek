# @TEST-DOC: Error in function declaration should not report argument mismatches at call site
# @TEST-EXEC-FAIL: zeek -b %INPUT > out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
module M;

export {
	type MyEnum: enum { MY_ENUM_A, MY_ENUM_B };
	global to_string: function(e: MyEnumTypo): string;
}

event zeek_init() {
	M::to_string(MY_ENUM_A);
}

event zeek_done() {
	M::to_string(MY_ENUM_B);
}

function helper(e: MyEnum): string {
	return M::to_string(e);
}
