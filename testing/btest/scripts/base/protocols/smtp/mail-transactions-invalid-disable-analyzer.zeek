# @TEST-EXEC: zeek -b -r $TRACES/smtp-mail-transactions-invalid.pcap %INPUT > out
# @TEST-EXEC: btest-diff smtp.log
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: btest-diff out

@load base/protocols/smtp

redef SMTP::max_invalid_mail_transactions = 2;

event connection_state_remove(c: connection)
	{
	if ( ! c$smtp_state?$analyzer_id )
		print network_time(), "smtp analyzer disabled", c$uid;
	}
