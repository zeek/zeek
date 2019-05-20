# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global test = md5_hash_init();

event zeek_init()
	{
	md5_hash_update(test, "one");
	md5_hash_update(test, "two");
	md5_hash_update(test, "three");
	print md5_hash_finish(test);
	}
