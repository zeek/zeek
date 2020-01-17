# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

local p1: pattern = /one|foo|bar/;
local p2: pattern = /two|oob/;
local p3: pattern = /three|oob/;
local p4 = /four/;

local p: set[pattern] = {p1, p2, p3, p4};

local t: table[pattern] of count = {
	[p1] = 0,
	[p2] = 1,
	[p3] = 2,
	[p4] = 3
};

local t2: table[pattern, count] of count = {
	[p1,2] = 0,
	[p2,3] = 2,
	[p3,4] = 4,
	[p4,5] = 6
};

print p1;
print p2;
print p3;
print p4;

print "-----------------";

for ( key in p )
	print key;

print "-----------------";

for ( key, value in t )
	print key, value;

print "-----------------";

for ( [c1, c2], value in t2)
	print c1, c2, value;
