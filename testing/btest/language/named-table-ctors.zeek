# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type MyRec: record {
	min: count &optional;
	max: count;
};

type FooTable: table[count] of string;
type FooTableRec: table[MyRec] of string;
type FooTableComp: table[string, count] of string;
type FooTableY: table[string] of double;

global mytable: FooTable = FooTable([1] = "one", [5] = "five", [3] = "three");
global mytablerec: FooTableRec = FooTableRec([[$max=5]] = "max5", [[$max=2]] = "max2");
global mytablecomp: FooTableComp = FooTableComp(["test", 1] = "test1", ["cool", 
2] = "cool2");
global mytabley: FooTableY = FooTableY(["one"] = 1, ["two"] = 2, ["three"] = 3) &default=0;

event zeek_init()
	{
	print mytable;
	print mytablerec;
	print mytablecomp;
	print mytabley;
	print mytabley["test"];

	local loctable = FooTable([42] = "forty-two", [37] = "thirty-seven");
	print loctable;
	}
