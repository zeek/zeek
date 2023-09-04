# @TEST-DOC: Check that extend-email/hostnames.zeek does not run lookup_addr() for non email type notices.
# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/frameworks/notice

@load frameworks/notice/extend-email/hostnames


redef enum Notice::Type += {
	Test_New_Connection_Notice,
	Test_Connection_State_Remove_Notice,
};

redef Notice::emailed_types += {
	Test_Connection_State_Remove_Notice,
};

redef Notice::mail_dest = "user@example.net";
redef Notice::sendmail = "fake-sendmail";  # not in effect, but better safe than sorry.


module Notice;

hook Notice::notice(n: Notice::Info) &priority=-2
	{
	# email_delay_token population runs at priority -1
	# in extend-email/hostnames.zeek, so we can look
	# at the result during priority=-2 and observe
	# that only Test_Connection_State_Remove_Notice
	# has email_delay_tokens set.
	print "email_delay_tokens", n$note, |n$email_delay_tokens| > 0 ? join_string_set(n$email_delay_tokens, ",") : "(empty)";
	}

event new_connection(c: connection)
	{
	NOTICE([$note=Test_New_Connection_Notice, $conn=c]);
	}

event connection_state_remove(c: connection)
	{
	NOTICE([$note=Test_Connection_State_Remove_Notice, $conn=c]);
	}
