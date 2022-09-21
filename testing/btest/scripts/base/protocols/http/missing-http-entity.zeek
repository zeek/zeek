# @TEST-DOC: The server starts sending a response while the client is still uploading the POST payload. This causes http_header to be raised while no entity is set.
# @TEST-EXEC: zeek -b -r $TRACES/http/interleaved-http-entity.pcap %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/http
@load base/frameworks/notice/weird
