# @TEST-DOC: Error in Record should not show when trying to coerce to it.
# @TEST-EXEC-FAIL: zeek -b %INPUT > out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
export {
	type MyEnum: enum { MY_ENUM_A, MY_ENUM_B };

	type MyRecord: record {
		e: MyEnumTypo;
		s: string;
	};
}

event zeek_init() {
	local r1 = MyRecord($e=MY_ENUM_B, $s="test");
	local r2: MyRecord = [$e=MY_ENUM_B, $s="test"];
}
