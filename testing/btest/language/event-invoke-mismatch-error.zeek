# @TEST-DOC: Error in event declaration should not report argument mismatches at call site
# @TEST-EXEC-FAIL: zeek -b %INPUT > out 2>&1
# @TEST-EXEC: btest-diff-remove-abspath out
module M;

export {
	type MyEnum: enum { MY_ENUM_A, MY_ENUM_B };
	global my_event: event(e: MyEnumTypo);
}

event zeek_init() {
	event my_event(MY_ENUM_A);
}

event zeek_done() {
	event my_event(MY_ENUM_B);
}

function helper(e: MyEnum){
	event my_event(e);
}
