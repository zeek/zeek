# @TEST-EXEC-FAIL: zeek -b %INPUT 2>out
# @TEST-EXEC: btest-diff-remove-abspath out

type Foo: record  {
	a: set[string] &default=set(1,2,3);
};

global f: Foo;
print f;
