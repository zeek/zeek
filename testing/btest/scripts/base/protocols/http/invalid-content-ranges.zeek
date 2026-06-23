# @TEST-DOC: Verify some invalid Content-Range headers.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/invalid-content-ranges.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m uid status_code status_msg http.log
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log

@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/notice/weird
