# @TEST-EXEC: zeek -b -r $TRACES/http/x-gzip.pcap base/protocols/http
# @TEST-EXEC: btest-diff http.log
