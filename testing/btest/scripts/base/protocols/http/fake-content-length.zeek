# @TEST-EXEC: zeek -r $TRACES/http/fake-content-length.pcap
# @TEST-EXEC: btest-diff http.log
