# @TEST-EXEC: bro -C -r $TRACES/web.trace %INPUT
# @TEST-EXEC: btest-diff alarm-mail.txt

redef Notice::policy += { [$action = Notice::ACTION_ALARM, $priority = 1 ] };
redef Notice::force_email_summaries = T;

redef enum Notice::Type += {
	Test_Notice,
};

event connection_established(c: connection)
	{
	NOTICE([$note=Test_Notice, $conn=c, $msg="test", $identifier="static"]);
	}



