# @TEST-DOC: Check the limitation on the number of client channels and repeat connect-initial packets
# @TEST-EXEC: zeek -b -r $TRACES/rdp/client-channel-memory-exhaustion.pcap %INPUT
# @TEST-EXEC: mv analyzer_debug.log analyzer_debug1.log
# @TEST-EXEC: btest-diff-cut -m analyzer_debug1.log
# @TEST-EXEC: zeek -b -r $TRACES/rdp/client-connect-initial-limit.pcap %INPUT
# @TEST-EXEC: mv analyzer_debug.log analyzer_debug2.log
# @TEST-EXEC: btest-diff-cut -m analyzer_debug2.log

@load base/protocols/rdp
@load frameworks/analyzer/debug-logging
