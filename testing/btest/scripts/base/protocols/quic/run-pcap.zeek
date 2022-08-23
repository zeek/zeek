# @TEST-DOC: Test that runs the pcap
# @TEST-EXEC: zeek -Cr $TRACES/quic/quic_win11_firefox_google.pcap base/protocols/quic >output
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ssl.log