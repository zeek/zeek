# @TEST-DOC: Previously, Zeek could be tricked into switchin to chunked mode using a Transfer-Encoding of a nested entity, this is a regression test.
# @TEST-EXEC: zeek -b -r $TRACES/http/smuggle-http-request.pcap %INPUT
# @TEST-EXEC: zeek-cut -m < http.log > http.log.cut
# @TEST-EXEC: zeek-cut -m < weird.log > weird.log.cut
# @TEST-EXEC: btest-diff http.log.cut
# @TEST-EXEC: btest-diff weird.log.cut

@load base/frameworks/notice/weird
@load base/protocols/http
