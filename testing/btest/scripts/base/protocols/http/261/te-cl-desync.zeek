# @TEST-DOC: Transfer-Encoding chunked and Content-Lenght used together is weird, shoudld be reported in weird.log
#
# @TEST-EXEC: zeek -b -r $TRACES/http/261/variant-04-te_cl_desync.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m uid trans_depth method host uri http.log
# @TEST-EXEC: btest-diff-cut -m uid name addl notice source weird.log

@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/notice/weird
