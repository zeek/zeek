# @TEST-DOC: HTTP response with Content-Length followed by HTTP/0.9 request. This triggered an assert.
# @TEST-EXEC: zeek -b -Cr $TRACES/http/http-09-content-length-confusion.pcap %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log

@load base/frameworks/notice/weird
@load base/protocols/http
