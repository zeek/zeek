# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

type FooSet: set[count];
type FooSetComp: set[string, count];

global myset: FooSet = FooSet(1, 5, 3);
global mysetcomp: FooSetComp = FooSetComp(["test", 1], ["cool", 2]);

print myset;
print mysetcomp;
