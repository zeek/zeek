# @TEST-DOC: Tests converting between lists and vectors with the 'as' keyword
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

type r: record {
        a: string;
        b: string;
};

print("vector to list");
local v1 = vector(1, 1, 1, 2, 2, 3, 3, 4);
local l1 = v1 as list of count;
print(v1);
print(l1);

print("");
print("list to vector (count)");
local l2 = list(1, 2, 3, 4);
local v2 = l2 as vector of count;
print(l2);
print(v2);

print("");
print("list to vector (port)");
local l3 = list(21/tcp, 23/tcp);
local v3 = l3 as vector of port;
print(l3);
print(v3);

local l: list of r = list([$a="a", $b="b"], [$a="a1", $b="b1"]);
local v: vector of r = vector([$a="a", $b="b"], [$a="a1", $b="b1"]);

print("");
print("list to vector (record)");
print l;
print v as list of r;

print("");
print("vector to list (record)");
print v;
print l as vector of r;
