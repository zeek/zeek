# @TEST-EXEC: zeek -C -r $TRACES/pppoe-over-qinq.pcap
# @TEST-EXEC: btest-diff conn.log
