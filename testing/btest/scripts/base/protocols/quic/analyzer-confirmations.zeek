# @TEST-DOC: Test the order of analyzer confirmations for QUIC and SSL, QUIC should come first.

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -r $TRACES/quic/chromium-115.0.5790.110-api-cirrus-com.pcap %INPUT >out
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff out
# @TEST-EXEC: btest-diff conn.log.cut

@load base/protocols/quic


event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
	{
	print "analyzer_confirmation", network_time(), info$c$uid, atype;
	}
