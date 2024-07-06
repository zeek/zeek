# @TEST-DOC: Test for correct ZAM optimization of record "chains".
#
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

type R: record {
	a: count;
	b: int;
	c: double;
};

type Rev_R: record {
	a: double;
	b: int;
	c: count;

	d: count;
	e: int;
	f: double;

	g: string;
};

global r1 = R($a = 3, $b = -12, $c = -42.3);
global r2 = R($a = 1003, $b = -10012, $c = -10042.3);

global r3: Rev_R;

r3$a = r1$c;
r3$b = r1$b;
r3$c = r1$a;
r3$d = r1$a;
r3$e = r2$b;
r3$f = r2$a;
r3$g = "tail";

print r3;

r3$a += r1$c;
r3$b += r1$b;
r3$g = "intervening";
r3$c += r2$a;
r3$d += r2$a;
r3$e += r2$b;
r3$f += r2$c;

print r3;
