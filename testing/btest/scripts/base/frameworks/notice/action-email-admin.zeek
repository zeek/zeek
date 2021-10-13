# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff sendmail.out
# @TEST-EXEC: btest-diff notice.log

@load base/frameworks/notice
@load base/utils/site

redef Notice::mail_dest = "user@example.net";
redef Notice::sendmail = "fake-sendmail";

redef Site::local_admins += {
	[1.0.0.0/8] = set("cloudflare@example.net", "postmaster@the.cloud"),
	[2.0.0.0/8] = set("2_dot@example.net"),
	};

redef enum Notice::Type += {
	Test_Notice,
};

event zeek_init()
	{
	NOTICE([$note=Test_Notice, $msg="test", $identifier="static", $src=1.1.1.1, $dst=2.2.2.2]);
	}

hook Notice::policy(n: Notice::Info) &priority=1
	{
	add n$actions[Notice::ACTION_EMAIL_ADMIN];
	}
