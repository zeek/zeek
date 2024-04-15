# @TEST-DOC: Test error cases while converting between sets and lists with the 'as' keyword
# @TEST-EXEC-FAIL: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath" btest-diff .stderr

print("list to set: type mismatch");
local l1 = list(1, 1, 1, 2, 2, 3, 3, 4);
local s1 = l1 as set[addr];
print(l1);
print(s1);

print("");
print("set to list: type mismatch");
local s2 = set(1, 2, 3, 4);
local l2 = s2 as list of addr;
print(s2);
print(l2);

print("");
print("set to list: multiple indices");
local s3: set[port,string] = { [21/tcp, "ftp"], [23/tcp, "telnet"] };
local l3 = s3 as list of port;
print(s3);
print(l3);
