# @TEST-EXEC: zeek -b %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff output

type foo: enum { a, b } &redef;

module test;

redef enum foo += { c };

export {
	type foo: enum { a, b };
}

event zeek_init()
	{
	print GLOBAL::a, GLOBAL::b, a, b, c;
	}
