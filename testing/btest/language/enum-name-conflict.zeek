# @TEST-EXEC-FAIL: zeek -b %INPUT  >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath" btest-diff output

type a: enum {
	RED,
	BLUE
};

type b: enum {
	BLUE,
	GREEN
};

redef enum b += {
	RED,
};

module Foo;

export {
	type af: enum {
		ONE,
		TWO
	};

	type bf: enum {
		TWO,
		THREE
	};

	redef enum bf += {
		ONE,
	};
}

module GLOBAL;

global NOPE = 37;

redef enum a += {
	NOPE,
};

type E: enum { Red, Green, Blue };
redef enum E += { Pink };
redef enum E += { Pink };

print Pink;
print Pink;
