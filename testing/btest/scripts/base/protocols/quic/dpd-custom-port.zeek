# @TEST-DOC: Test that QUICv1 DPD detects QUIC on a non-standard port (chromium pcap, 443 rewritten to 4433).

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -r $TRACES/quic/chromium-dpd-custom-port-4433.pcap base/protocols/quic
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff quic.log
