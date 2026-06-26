# @TEST-DOC: Test that QUICv1 DPD detects QUIC on a non-standard port (chromium pcap, 443 rewritten to 4433).

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -r $TRACES/quic/chromium-dpd-custom-port-4433.pcap base/protocols/quic
# @TEST-EXEC: btest-diff-cut -m uid history service conn.log
# @TEST-EXEC: btest-diff-cut -m quic.log
