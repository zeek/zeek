# @TEST-EXEC: zeek -b %INPUT
# The "Test_Notice" should be logged twice
# @TEST-EXEC: test `grep Test_Notice notice.log | wc -l` -eq 2

@load base/frameworks/notice

redef enum Notice::Type += {
	Test_Notice,
};

redef Notice::not_suppressed_types += { Test_Notice };

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
