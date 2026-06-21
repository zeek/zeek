# @TEST-DOC: Test that QUICv2 DPD detects QUIC on a non-standard port (quicv2-echo pcap, 443 rewritten to 4433).

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -r $TRACES/quic/quicv2-echo-dpd-custom-port-4433.pcap base/protocols/quic
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff quic.log
