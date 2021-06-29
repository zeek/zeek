# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff sendmail.out

# Tests overriding the e-mail destination for a specific notice


@load base/frameworks/notice

hook Notice::policy(n: Notice::Info) &priority=1
	{
	add n$actions[Notice::ACTION_EMAIL];
	}

redef Notice::mail_dest = "user@example.net";
redef Notice::sendmail = "fake-sendmail";

redef enum Notice::Type += {
	Test_Notice,
};

event zeek_init()
	{
	NOTICE([$note=Test_Notice, $msg="test", $identifier="static"]);
	}

hook Notice::policy(n: Notice::Info)
	{
	n$email_dest = set("admin@example.net");
	}
