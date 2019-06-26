# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type MyRecord: record {
	a: count &default=13;
	c: count;
	v: vector of string &default=vector();
};

type Foo: record {
	foo: count;
	quux: count &default=9876;
};

type Bar: record {
	bar: count;
	foo: Foo &default=[$foo=1234];
};

function print_bar(b: Bar)
	{
	print b;
	print b$foo;
	print b$foo$quux;
	}

global bar:  Bar = [$bar=4321];
global bar2: Bar = [$bar=4231, $foo=[$foo=1000]];
global bar3: Bar = [$bar=4321, $foo=[$foo=10, $quux=42]];

print_bar(bar);
print_bar(bar2);
print_bar(bar3);

local bar4: Bar = [$bar=100];
local bar5: Bar = [$bar=100, $foo=[$foo=1001]];
local bar6: Bar = [$bar=100, $foo=[$foo=11, $quux=7]];

print_bar(bar4);
print_bar(bar5);
print_bar(bar6);

local r: MyRecord = [$c=13];
print r;
print |r$v|;
r$v += "test";
print r;
print |r$v|;
