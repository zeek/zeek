# @TEST-DOC: HTTP QUERY method (RFC 10008) on a non-standard port detected via DPD.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/query-method-non-standard-port.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m http.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
#
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: test ! -f analyzer.log

@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/notice/weird
