# Check that data contained in the ethernet padding does not make it into protocol analysis

# @TEST-EXEC: zeek -C -r $TRACES/tcp-http-with-padding.pcap %INPUT >out
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log

