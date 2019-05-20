# @TEST-EXEC: zeek -C -r $TRACES/radiotap.pcap
# @TEST-EXEC: btest-diff conn.log
