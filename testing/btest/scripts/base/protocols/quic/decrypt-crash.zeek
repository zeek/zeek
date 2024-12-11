# @TEST-DOC: Trace produced by OSS-Fuzz triggered a crash due to using a too small local buffer for decryption.

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -Cr $TRACES/quic/383379789-decrypt-crash.pcap base/protocols/quic %INPUT
# @TEST-EXEC: zeek-cut -m ts uid proto history service < conn.log > conn.log.cut
# @TEST-EXEC: zeek-cut -m ts uid cause analyzer_kind analyzer_name failure_reason < analyzer.log > analyzer.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER='sed -E "s/\((.+)\.spicy:[0-9]+:[0-9]+(-[0-9]+:[0-9]+)?\)/(\1.spicy:<location>)/g" | $SCRIPTS/diff-remove-abspath' btest-diff analyzer.log.cut
