# @TEST-DOC: Tests converting between sets and vectors with the 'as' keyword
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

type r: record {
        a: string;
        b: string;
};

print("vector to set");
local v1 = vector(1, 1, 1, 2, 2, 3, 3, 4);
local s1 = v1 as set[count];
print(v1);
print(s1);

print("");
print("set to vector (count)");
local s2 = set(1, 2, 3, 4);
local v2 = s2 as vector of count;
print(s2);
print(v2);

print("");
print("set to vector (port)");
local s3 = set(21/tcp, 23/tcp);
local v3 = s3 as vector of port;
print(s3);
print(v3);

local s: set[r] = set([$a="a", $b="b"], [$a="a1", $b="b1"]);
local v: vector of r = vector([$a="a", $b="b"], [$a="a1", $b="b1"]);

print("");
print("set to vector (record)");
print s;
print v as set[r];

print("");
print("vector to set (record)");
print v;
print s as vector of r;
