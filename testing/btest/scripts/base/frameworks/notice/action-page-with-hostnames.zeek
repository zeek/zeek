# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff sendmail.out

@load base/frameworks/notice
@load frameworks/notice/extend-email/hostnames

redef Notice::mail_dest = "user@example.net";
redef Notice::mail_page_dest = "page@example.net";
redef Notice::sendmail = "fake-sendmail";

redef enum Notice::Type += {
	Test_Notice,
};

event zeek_init()
	{
	NOTICE([$note=Test_Notice, $msg="test", $identifier="static", $src=1.1.1.1, $dst=[::1]]);
	}

hook Notice::policy(n: Notice::Info) &priority=1
	{
	add n$actions[Notice::ACTION_PAGE];
	}
