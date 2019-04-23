# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

print md5_hash("one");
print md5_hash("one", "two", "three");

local a = md5_hash_init();
local b = md5_hash_init();

md5_hash_update(a, "one");
md5_hash_update(b, "one");
md5_hash_update(b, "two");
md5_hash_update(b, "three");

print md5_hash_finish(a);
print md5_hash_finish(b);

print md5_hmac("one");
print md5_hmac("one", "two", "three");
