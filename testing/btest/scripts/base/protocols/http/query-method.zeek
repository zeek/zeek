# @TEST-DOC: HTTP QUERY method (RFC 10008) request with a JSON body and 200 OK response.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/query-method.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m http.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
#
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: test ! -f analyzer.log

@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/notice/weird
