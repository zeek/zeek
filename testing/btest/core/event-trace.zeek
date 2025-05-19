# @TEST-DOC: Verify the --event-trace feature works and produces the same logs as when reading from a pcap.
#
# Trace files produced with ZAM don't work - issue #4478
#
# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
#
# @TEST-EXEC: zeek --event-trace trace.zeek -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: mkdir pcap-logs
# @TEST-EXEC: zeek-cut -m < http.log > pcap-logs/http.log
# @TEST-EXEC: rm -v *.log
#
# @TEST-EXEC: zeek -b --parse-only %INPUT trace.zeek
# @TEST-EXEC: zeek -b %INPUT trace.zeek
# @TEST-EXEC: mkdir trace-logs
# @TEST-EXEC: zeek-cut -m < http.log > trace-logs/http.log
# @TEST-EXEC: rm -v *.log
#
# @TEST-EXEC: diff pcap-logs/http.log trace-logs/http.log
# @TEST-EXEC: btest-diff .stderr

@load base/protocols/http
