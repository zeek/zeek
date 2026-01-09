# @TEST-DOC: An inner MIME message specifying Transfer-Encoding confused the state machine, triggering an assert in debug builds and potentially allowing to smuggle HTTP requests.
# @TEST-EXEC: zeek -b -r $TRACES/http/http-inner-transfer-encoding-reproducer.pcap %INPUT
# @TEST-EXEC: zeek-cut -m < http.log > http.log.cut
# @TEST-EXEC: zeek-cut -m < weird.log > weird.log.cut
# @TEST-EXEC: btest-diff http.log.cut
# @TEST-EXEC: btest-diff weird.log.cut

@load base/frameworks/notice/weird
@load base/protocols/http
