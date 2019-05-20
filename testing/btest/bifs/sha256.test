# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

print sha256_hash("one");
print sha256_hash("one", "two", "three");

local a = sha256_hash_init();
local b = sha256_hash_init();

sha256_hash_update(a, "one");
sha256_hash_update(b, "one");
sha256_hash_update(b, "two");
sha256_hash_update(b, "three");

print sha256_hash_finish(a);
print sha256_hash_finish(b);
