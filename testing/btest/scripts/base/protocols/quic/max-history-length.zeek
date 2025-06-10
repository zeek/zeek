# @TEST-DOC: Test that runs the pcap
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -r $TRACES/quic/firefox-102.13.0esr-blog-cloudflare-com.pcap base/protocols/quic QUIC::max_history_length=3
# @TEST-EXEC: zeek-cut -m ts uid history < quic.log > quic.log.cut
# @TEST-EXEC: btest-diff quic.log.cut
# @TEST-EXEC: btest-diff weird.log
