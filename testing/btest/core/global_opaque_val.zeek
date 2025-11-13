# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global test = sha1_hash_init();

event zeek_init()
	{
	sha1_hash_update(test, "one");
	sha1_hash_update(test, "two");
	sha1_hash_update(test, "three");
	print sha1_hash_finish(test);
	}
