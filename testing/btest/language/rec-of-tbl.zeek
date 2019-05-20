# @TEST-EXEC: zeek -b %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff output

type x: record {
	a: table[int] of count;
};

global y: x;

global yy: table[int] of count;

y$a = yy;

y$a[+5] = 3;

print y;
