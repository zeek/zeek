# @TEST-EXEC: zeek -b -r $TRACES/http/content-range-less-than-len.pcap %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/http
@load base/frameworks/notice/weird
