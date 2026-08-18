# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff-remove-abspath out
module MyModule;

export {
	type MyEnum: enum {
		MY_ENUM_A,
		MY_ENUM_B,
	};

	type MyRec: record {
		a: MyEnumTypo &default=MY_ENUM_A;
	};
}
