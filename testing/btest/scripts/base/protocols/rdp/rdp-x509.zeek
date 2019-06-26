# @TEST-EXEC: zeek -r $TRACES/rdp/rdp-x509.pcap %INPUT
# @TEST-EXEC: btest-diff rdp.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-timestamps | $SCRIPTS/diff-remove-x509-key-info" btest-diff x509.log

@load base/protocols/rdp
