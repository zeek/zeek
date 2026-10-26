# @TEST-DOC: Similar to http-pending-state-growth, but different PCAP
#
# @TEST-EXEC: zcat <$TRACES/http/http-unanswered-request-memory-exhaustion.pcap.gz | zeek -C -b -r - %INPUT >out
# @TEST-EXEC: echo "total http.log lines" >>out
# @TEST-EXEC: grep -v '^#' http.log | wc -l | sed 's/ //g' >>out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/conn
@load base/protocols/http
