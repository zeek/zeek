# @TEST-DOC: Test that runs the pcap

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -Cr $TRACES/quic/vector-max-size-crash.pcap base/protocols/quic %INPUT > out
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: zeek-cut -m ts uid cause analyzer_kind analyzer_name failure_reason < analyzer.log > analyzer.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff quic.log

# @TEST-EXEC: TEST_DIFF_CANONIFIER='sed -E "s/\((.+)\.spicy:[0-9]+:[0-9]+(-[0-9]+:[0-9]+)?\)/(\1.spicy:<location>)/g" | $SCRIPTS/diff-remove-abspath' btest-diff analyzer.log.cut

event QUIC::unhandled_version(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	print "QUIC::unhandled_version", c$uid, is_orig, version, dcid, scid;
	}
