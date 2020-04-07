# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

local test_string = "foo";
local myvec: vector of pattern = vector(/a/, /b/, /o/);
local myset: set[pattern] = {/a/, /b/, /o/};
local tk: table[pattern] of count = {[/a/] = 0, [/b/] = 1, [/o/] = 2};
local tv: table[count] of pattern = {[0] = /a/, [1] = /b/, [2] = /o/};

print /a/, /a/ in test_string;
print /b/, /b/ in test_string;
print /o/, /o/ in test_string;

print "---";

for ( i in myvec )
	print myvec[i], myvec[i] in test_string;

print "---";

for ( p in myset )
	print p, p in test_string;

print "---";

for ( k, v in tk )
	print k, k in test_string;

print "---";

for ( key, val in tv )
	print val, val in test_string;
