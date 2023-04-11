# @TEST-EXEC: zeek -b -r $TRACES/smtp-mail-transactions-invalid.pcap %INPUT > out
# @TEST-EXEC: btest-diff smtp.log
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: btest-diff out

@load base/protocols/smtp

redef SMTP::max_invalid_mail_transactions = 2;

hook Analyzer::disabling_analyzer(c: connection, atype: AllAnalyzers::Tag, aid: count)
	{
	print network_time(), "disabling_analyzer", c$uid, atype, aid;
	}
