# @TEST-DOC: Test that runs the pcap

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -Cr $TRACES/quic/vector-max-size-crash.pcap base/protocols/quic
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: zeek-cut -m ts uid cause analyzer_kind analyzer_name failure_reason < analyzer.log > analyzer.log.cut
# @TEST-EXEC: btest-diff conn.log.cut

# Only run btest-ddiff on analyzer.log with 6.1-dev or later. The violation
# reporting has more detail in later versions.
# @TEST-EXEC: zeek -b -e 'exit(Version::info$version_number < 60100 ? 0 : 1)' || TEST_DIFF_CANONIFIER='sed -r "s/\((.+)\.spicy:[0-9]+:[0-9]+\)/(\1.spicy:<line>:<column>)/g" | $SCRIPTS/diff-remove-abspath' btest-diff analyzer.log.cut
