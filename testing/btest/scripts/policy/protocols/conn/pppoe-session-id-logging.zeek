# A basic test of pppoe session id logging

# @TEST-EXEC: zeek -b -r $TRACES/pppoe-over-qinq.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load protocols/conn/pppoe-session-id-logging
