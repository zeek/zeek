# A basic test of pppoe session id logging

# @TEST-EXEC: zeek -b -r $TRACES/pppoe-over-qinq.pcap %INPUT
# @TEST-EXEC: zeek-cut -m uid id.orig_h id.orig_p id.resp_h id.resp_p pppoe_session_id < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut

@load protocols/conn/pppoe-session-id-logging
