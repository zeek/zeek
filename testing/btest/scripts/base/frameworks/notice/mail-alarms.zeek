# @TEST-EXEC: zeek -C -r $TRACES/web.trace %INPUT
# @TEST-EXEC: btest-diff alarm-mail.txt

hook Notice::policy(n: Notice::Info) &priority=1
	{
	add n$actions[Notice::ACTION_ALARM];
	}

redef Notice::force_email_summaries = T;

redef enum Notice::Type += {
	Test_Notice,
};

event connection_established(c: connection)
	{
	NOTICE([$note=Test_Notice, $conn=c, $msg="test", $identifier="static"]);
	}



