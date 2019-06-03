# @TEST-EXEC: zeek -C -r $TRACES/wlanmon.pcap
# @TEST-EXEC: btest-diff conn.log
