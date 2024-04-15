# @TEST-DOC: Tests converting between sets and lists with the 'as' keyword
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

type r: record {
        a: string;
        b: string;
};

print("list to set");
local l1 = list(1, 1, 1, 2, 2, 3, 3, 4);
local s1 = l1 as set[count];
print(l1);
print(s1);

print("");
print("set to list (count)");
local s2 = set(1, 2, 3, 4);
local l2 = s2 as list of count;
print(s2);
print(l2);

print("");
print("set to list (port)");
local s3 = set(21/tcp, 23/tcp);
local l3 = s3 as list of port;
print(s3);
print(l3);

local s: set[r] = set([$a="a", $b="b"], [$a="a1", $b="b1"]);
local l: list of r = list([$a="a", $b="b"], [$a="a1", $b="b1"]);

print("");
print("set to list (record)");
print s;
print l as set[r];

print("");
print("list to set (record)");
print l;
print s as list of r;
