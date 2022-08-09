# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out

type r: record { a: count; };

module test;

type r: record { b: count; };

event zeek_init()
	{
	local x: GLOBAL::r;
	x$a = 5;

	local y: test::r;
	y$b = 6;

	print(x);
	print(y);
	}
