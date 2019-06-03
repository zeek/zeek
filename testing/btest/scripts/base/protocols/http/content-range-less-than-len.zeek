# @TEST-EXEC: zeek -r $TRACES/http/content-range-less-than-len.pcap
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log
