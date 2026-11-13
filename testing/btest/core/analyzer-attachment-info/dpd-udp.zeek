# @TEST-DOC: Test the analyzer_attachment_info() record for DPD over UDP using KRB
#
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -r ${TRACES}/krb/auth.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/conn
@load-sigs base/protocols/krb/dpd.sig

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
