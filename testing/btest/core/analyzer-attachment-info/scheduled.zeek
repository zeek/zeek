# @TEST-DOC: Test the analyzer_attachment_info() record for scheduled analyzer (FTP data connection)
#
# @TEST-EXEC: zeek -b -r $TRACES/ftp/bigtransfer.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/ftp

event new_connection(c: connection)
	{
	print "new_connection", c$uid;
	}

event analyzer_attachment_info(tag: AllAnalyzers::Tag, info: AnalyzerAttachmentInfo)
	{
	print "analyzer_attachment_info", info$c$uid, tag, info$reason, info$aid, info$parent_aid;
	}

event analyzer_confirmation_info(tag: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
	{
	print "analyzer_confirmation_info", info$c$uid, tag, info$aid;
	}
