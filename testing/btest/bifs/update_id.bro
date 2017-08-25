# @TEST-EXEC: bro -b %INPUT >output
# @TEST_EXEC: btest-diff output

const test_config = "init" &redef;

event my_event()
	{
	print test_config;
	}

event bro_init()
	{
	print test_config;
	print update_ID("test_config", "updated");
	local s = "locals can't be updated";
	print update_ID("no", "local updated");
	print s;
	event my_event();
	}
