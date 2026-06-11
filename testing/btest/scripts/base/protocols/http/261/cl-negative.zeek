# @TEST-DOC: Ensure negative Content-Length are reported as weirds.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/261/variant-03-cl_negative.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m uid trans_depth method host uri http.log
# @TEST-EXEC: btest-diff-cut -m uid name addl notice source weird.log

@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/notice/weird
