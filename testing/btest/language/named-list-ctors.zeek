# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type MyRec: record {
	min: count &optional;
	max: count;
};

type FooList: list of string;
type FooListD: list of double;
type FooListRec: list of MyRec;

global mylist: FooList = FooList("one", "two", "three");
global mylistd: FooListD = FooListD(1, 2, 3);
global mylistrec: FooListRec = FooListRec([$max=1], [$max=2], [$max=3]);

print mylist;
print mylistd;
print mylistrec;
