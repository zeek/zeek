# @TEST-DOC: Socks V5 over a non-standard port.

# @TEST-EXEC: zeek -r $TRACES/socks-auth-10080.pcap %INPUT
# @TEST-EXEC: zeek-cut -m id.orig_h id.orig_p id.resp_h id.resp_p service history < conn.log > conn.log.cut
# @TEST-EXEC: zeek-cut -m id.orig_h id.orig_p id.resp_h id.resp_p version status bound.host bound.name bound_p < socks.log > socks.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff socks.log.cut

@load base/protocols/socks

redef SOCKS::default_capture_password = T;
