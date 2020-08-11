# @TEST-EXEC: zeek -b -Cr $TRACES/http/no-uri.pcap %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/http
@load base/frameworks/notice/weird
