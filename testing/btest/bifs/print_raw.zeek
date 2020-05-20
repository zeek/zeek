# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

local j = to_json("\x07\xd4\xb7o");

local v: vector of count = vector();
v += 9;
v += 10;

print_raw(j, "\n");
print_raw("start ", j, 137, T, v, " finish", "\n");
print_raw("\xc3\xa9", "\n");
