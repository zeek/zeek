# @TEST-DOC: Pcap with CRYPTO frames fragemented over multiple INITIAL packets. The pcap only contains 3 INITIAL packets. Check what logs are created.

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -r $TRACES/quic/quic-multiple-initial-fragmented-crypto-only-initial.pcap base/protocols/quic
# @TEST-EXEC: test ! -f analyzer.log
# @TEST-EXEC: test ! -f dpd.log
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: zeek-cut -m ts uid server_name history < quic.log > quic.log.cut
# @TEST-EXEC: btest-diff quic.log.cut
# @TEST-EXEC: zeek-cut -m ts uid version cipher curve server_name resumed last_alert next_protocol established ssl_history < ssl.log > ssl.log.cut
# @TEST-EXEC: btest-diff ssl.log.cut
