# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

print sha1_hash("one");
print sha1_hash("one", "two", "three");

local a = sha1_hash_init();
local b = sha1_hash_init();

sha1_hash_update(a, "one");
sha1_hash_update(b, "one");
sha1_hash_update(b, "two");
sha1_hash_update(b, "three");

print sha1_hash_finish(a);
print sha1_hash_finish(b);
