# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

type X: record {
     a: count &optional;
     b: count &default=5;
};

function p(x: X)
	{
	print x?$a ? fmt("a: %d", x$a) : "a: not set";
	print x$b;
	}


global x: X = [$a=20, $b=20];
p(x);
delete x$a;
delete x$b;
p(x);
