# @TEST-EXEC: zeek -b -r $TRACES/q-in-q.pcap base/protocols/conn
# @TEST-EXEC: btest-diff conn.log
