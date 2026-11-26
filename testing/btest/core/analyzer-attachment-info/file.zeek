# @TEST-DOC: Test the analyzer_attachment_info() record for a PE file over FTP.
#
# @TEST-EXEC: zeek -b -r $TRACES/pe/pe.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/ftp
@load base/files/pe

event new_connection(c: connection)
	{
	print "new_connection", c$uid;
	}

event analyzer_attachment_info(tag: AllAnalyzers::Tag, info: AnalyzerAttachmentInfo)
	{
	print "analyzer_attachment_info", info?$c ? cat("conn ", info$c$uid) : cat("file ", info$f$id), tag, info$reason;
	}

event analyzer_confirmation_info(tag: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
	{
	print "analyzer_confirmation_info", info$c$uid, tag, info$aid;
	}
