# @TEST-EXEC: bro -r $TRACES/http/content-range-less-than-len.pcap
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log
