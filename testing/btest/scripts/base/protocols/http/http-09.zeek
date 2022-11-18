# @TEST-DOC: Artificially created PCAP with one proper HTTP 0.9 request/response and a few invalid ones.
# @TEST-EXEC: zeek -b -Cr $TRACES/http/http_09.pcap %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log

@load base/frameworks/notice/weird
@load base/protocols/http
