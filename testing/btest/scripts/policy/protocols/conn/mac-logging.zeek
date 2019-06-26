# A basic test of the mac logging script

# @TEST-EXEC: zeek -b -C -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: mv conn.log conn1.log
# @TEST-EXEC: zeek -b -C -r $TRACES/radiotap.pcap %INPUT
# @TEST-EXEC: mv conn.log conn2.log
# @TEST-EXEC: zeek -b -C -r $TRACES/llc.pcap %INPUT
# @TEST-EXEC: mv conn.log conn3.log
#
# @TEST-EXEC: btest-diff conn1.log
# @TEST-EXEC: btest-diff conn2.log
# @TEST-EXEC: btest-diff conn3.log

@load protocols/conn/mac-logging
