# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

local s: set[list of count] = set();
local ss: set[list of count, list of count] = set();

add s[list(1)];
add s[list(2, 3)];
add s[list(4, 5, 6)];

add ss[list(1), list(2)];
add ss[list(1, 2), list(3, 4, 5)];

print s;
print list(1) in s;
print list(2) !in s;
print list(2, 3) in s;
print list(4, 5, 6) in s;

print ss;
print [list(1), list(2)] in ss;
print [list(1), list(1)] !in ss;
print [list(1, 2), list(3, 4)] !in ss;
print [list(1, 2), list(3, 4, 5)] in ss;
