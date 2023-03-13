# @TEST-EXEC: zeek -b -r $TRACES/http/http-bad-content-range-01.pcap %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/http
@load base/frameworks/notice/weird