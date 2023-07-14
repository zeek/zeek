# @TEST-DOC: Test error cases while converting between sets and vectorswith the 'as' keyword
# @TEST-EXEC-FAIL: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath" btest-diff .stderr

print("vector to set: type mismatch");
local v1 = vector(1, 1, 1, 2, 2, 3, 3, 4);
local s1 = v1 as set[addr];
print(v1);
print(s1);

print("");
print("set to vector: type mismatch");
local s2 = set(1, 2, 3, 4);
local v2 = s2 as vector of addr;
print(s2);
print(v2);

print("");
print("set to vector: multiple indices");
local s3: set[port,string] = { [21/tcp, "ftp"], [23/tcp, "telnet"] };
local v3 = s3 as vector of port;
print(s3);
print(v3);
