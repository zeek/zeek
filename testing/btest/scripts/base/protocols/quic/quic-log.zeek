# @TEST-DOC: Smoke test the quic.log production
#
# @TEST-EXEC: zeek -Cr $TRACES/quic/chromium-115.0.5790.110-google-de-fragmented.pcap base/protocols/quic
# @TEST-EXEC: btest-diff quic.log
# @TEST-EXEC: btest-diff .stderr
