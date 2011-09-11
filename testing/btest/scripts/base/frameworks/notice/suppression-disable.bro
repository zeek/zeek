# @TEST-EXEC: bro -b %INPUT
# @TEST-EXEC: btest-diff notice.log

@load base/frameworks/notice

redef enum Notice::Type += {
	Test_Notice,
};

redef Notice::not_suppressed_types += { Test_Notice };

event bro_init()
	{
	NOTICE([$note=Test_Notice, $msg="test", $identifier="static"]);
	NOTICE([$note=Test_Notice, $msg="another test", $identifier="static"]);
	}