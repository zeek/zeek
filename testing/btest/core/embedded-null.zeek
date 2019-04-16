# @TEST-EXEC: bro -b %INPUT 2>&1
# @TEST-EXEC: btest-diff .stdout

event bro_init()
	{
	local a = "hi\x00there";
	unique_id(a);
	}
