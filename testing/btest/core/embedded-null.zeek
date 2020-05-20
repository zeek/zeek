# @TEST-EXEC: zeek -b %INPUT 2>&1
# @TEST-EXEC: btest-diff .stdout

event zeek_init()
	{
	local a = "hi\x00there";
	unique_id(a);
	}
