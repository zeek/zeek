# @TEST-EXEC: cat %INPUT
# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global vec = vector(, 99, 99);

@TEST-START-NEXT
global vec = vector(99, 99, , );

@TEST-START-NEXT
global rec = [,];

@TEST-START-NEXT
type MyRecord: record {
	a: string;
};
global rec = MyRecord(,$a="aaa");

@TEST-START-NEXT
type MyRecord: record {
	a: string;
};
global rec = MyRecord($a="aaa", ,);

@TEST-START-NEXT
function f(x: count, y: count, ) { }

@TEST-START-NEXT
function f(x: count, y: count) { }
f(, 1, 2);

@TEST-START-NEXT
function f(x: count, y: count) { }
f(1, 2, ,);

@TEST-START-NEXT
global tab: table[string, string] of string;
tab["abc", "def", ] = "ghi";

@TEST-START-NEXT
global tab: table[string, string] of string;
tab[, "abc", "def"] = "ghi";

@TEST-START-NEXT
global tab: table[string, string] of string = {
	["abc", "def", ] = "ghi",
};

@TEST-START-NEXT
global tab = table(
	["abc", "def", ] = "ghi",
);
