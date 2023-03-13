# @TEST-EXEC: zeek -b base/protocols/http -r $TRACES/http/http-bad-content-range-01.pcap
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log
