# @TEST-EXEC-FAIL: zeek -b %INPUT 2>out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type Foo: record  {
	a: set[string] &default=set(1,2,3);
};

global f: Foo;
print f;
