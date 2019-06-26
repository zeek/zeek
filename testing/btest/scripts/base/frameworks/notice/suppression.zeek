# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff notice.log

@load base/frameworks/notice

redef enum Notice::Type += {
	Test_Notice,
};

# The second notice needs to be scheduled due to how the notice framework
# uses the event queue.

event second_notice()
	{
	NOTICE([$note=Test_Notice, $msg="another test", $identifier="static"]);
	}

event zeek_init()
	{
	NOTICE([$note=Test_Notice, $msg="test", $identifier="static"]);
	schedule 1msec { second_notice() };
	}

