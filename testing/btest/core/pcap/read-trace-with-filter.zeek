# @TEST-EXEC: zeek -r $TRACES/wikipedia.pcap -f "port 50000"
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff packet_filter.log
