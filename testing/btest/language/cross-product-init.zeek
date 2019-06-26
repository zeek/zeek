# @TEST-EXEC: zeek -b %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff output

global my_subs = { 1.2.3.4/19, 5.6.7.8/21 };

global x: set[string, subnet] &redef;

redef x += { [["foo", "bar"], my_subs] };

print x;
