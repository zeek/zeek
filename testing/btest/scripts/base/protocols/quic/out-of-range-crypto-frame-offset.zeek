# @TEST-DOC: Pcap CRYPTO frames with data far beyond offset 2**14+256 result in an analyzer violation after the initial confirmation.

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -Cr $TRACES/quic/quic-sparse-crypto-offset-state-exhaustion.pcap base/protocols/quic
# @TEST-EXEC: btest-diff-cut -m ts uid history service conn.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-locations | $SCRIPTS/diff-remove-spicy-abspath" btest-diff-cut -m analyzer.log
