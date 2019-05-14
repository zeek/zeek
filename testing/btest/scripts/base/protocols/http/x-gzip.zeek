# @TEST-EXEC: zeek -r $TRACES/http/x-gzip.pcap
# @TEST-EXEC: btest-diff http.log
