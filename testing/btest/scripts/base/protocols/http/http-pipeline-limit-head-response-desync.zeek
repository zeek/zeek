# @TEST-DOC: 10 GET requests followed by 5 HEAD request pipelined with the GET responses only coming in after the first HEAD request. Setting HTTP::max_pending_requests to 10 to trigger HTTP_excessive_pipelining
#
# @TEST-EXEC: zeek -C -b -r $TRACES/http/http-pipeline-limit-head-response-desync.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m http.log
# @TEST-EXEC: btest-diff-cut -m weird.log
# @TEST-EXEC: test ! -f analyzer.log

@load base/protocols/conn
@load base/protocols/http

redef HTTP::max_pending_requests = 10;
