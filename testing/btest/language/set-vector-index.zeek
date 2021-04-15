# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

local s: set[vector of count] = set();
local ss: set[vector of count, vector of count] = set();

add s[vector(1)];
add s[vector(2, 3)];
add s[vector(4, 5, 6)];

add ss[vector(1), vector(2)];
add ss[vector(1, 2), vector(3, 4, 5)];

print s;
print vector(1) in s;
print vector(2) !in s;
print vector(2, 3) in s;
print vector(4, 5, 6) in s;

print ss;
print [vector(1), vector(2)] in ss;
print [vector(1), vector(1)] !in ss;
print [vector(1, 2), vector(3, 4)] !in ss;
print [vector(1, 2), vector(3, 4, 5)] in ss;
