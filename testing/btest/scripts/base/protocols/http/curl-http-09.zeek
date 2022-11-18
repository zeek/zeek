# @TEST-DOC: curl --http0.9 to accept the headerless response.
# @TEST-EXEC: zeek -b -Cr $TRACES/http/curl_http_09.pcap %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: test ! -f weird.log

@load base/frameworks/notice/weird
@load base/protocols/http
